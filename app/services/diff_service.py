import difflib
import logging
import html
from typing import Optional, List, Dict, Any
from sqlalchemy.orm import Session
from app.models.backup import Backup, BackupStatus
import os
from app.services.backup_diagnostics import normalize_config_lines


class DiffService:
    """Serviço para comparação de configurações de backup."""

    # Base path for backup storage - Docker mount path
    STORAGE_BASE = '/app/storage/backups'

    @staticmethod
    def resolve_backup_path(backup: Backup) -> Optional[str]:
        """Resolve o caminho físico do arquivo de backup."""
        if not backup.file_path:
            return None
        if os.path.isabs(backup.file_path):
            return backup.file_path
        return os.path.join(DiffService.STORAGE_BASE, backup.file_path)

    @staticmethod
    def _normalize_content_for_diff(content: str) -> List[str]:
        """
        Normaliza conteúdo para comparação:
        - remove diferenças de EOL
        - remove linhas voláteis (timestamp/header/geradas automaticamente)
        """
        lines, _ = normalize_config_lines(content or "")
        return lines
    
    @staticmethod
    def read_backup_content(backup: Backup) -> Optional[str]:
        """Lê o conteúdo de um arquivo de backup."""
        file_path = DiffService.resolve_backup_path(backup)
        if not file_path:
            return None
        
        if not os.path.exists(file_path):
            logging.getLogger(__name__).warning("Backup file not found: %s", file_path)
            return None
        
        try:
            with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
                return f.read()
        except Exception as e:
            logging.getLogger(__name__).warning("failed to read backup file: %s", e)
            return None

    @staticmethod
    def compare_backups(backup_old: Backup, backup_new: Backup) -> Dict[str, Any]:
        """
        Compara dois backups e retorna o diff em formato estruturado.
        
        Returns:
            Dict com:
                - has_changes: bool
                - added_lines: int
                - removed_lines: int
                - hunks: List[Dict] - blocos de mudanças formatados
                - error: str or None
        """
        content_old = DiffService.read_backup_content(backup_old)
        content_new = DiffService.read_backup_content(backup_new)
        
        if content_old is None or content_new is None:
            return {
                'has_changes': False,
                'error': 'Não foi possível ler um ou ambos os arquivos de backup.',
                'added_lines': 0,
                'removed_lines': 0,
                'hunks': []
            }
        
        lines_old, dropped_old = normalize_config_lines(content_old)
        lines_new, dropped_new = normalize_config_lines(content_new)
        
        # Gera diff unificado
        diff_lines = list(difflib.unified_diff(
            lines_old,
            lines_new,
            fromfile=f"backup_{backup_old.created_at.strftime('%Y-%m-%d_%H-%M-%S')}.rsc",
            tofile=f"backup_{backup_new.created_at.strftime('%Y-%m-%d_%H-%M-%S')}.rsc",
            lineterm=''
        ))
        
        # Conta linhas adicionadas/removidas
        added = sum(1 for line in diff_lines if line.startswith('+') and not line.startswith('+++'))
        removed = sum(1 for line in diff_lines if line.startswith('-') and not line.startswith('---'))
        
        # Processa o diff em hunks estruturados para exibição
        hunks = DiffService._parse_unified_diff(diff_lines, lines_old, lines_new)
        
        return {
            'has_changes': len(diff_lines) > 0 and (added > 0 or removed > 0),
            'added_lines': added,
            'removed_lines': removed,
            'hunks': hunks,
            'total_lines_old': len(lines_old),
            'total_lines_new': len(lines_new),
            'ignored_lines_old': int(dropped_old),
            'ignored_lines_new': int(dropped_new),
            'error': None
        }
    
    @staticmethod
    def _parse_unified_diff(diff_lines: List[str], lines_old: List[str], lines_new: List[str]) -> List[Dict]:
        """
        Converte unified diff em estrutura de hunks para renderização.
        Cada hunk contém linhas com tipo (add/remove/context/header).
        """
        hunks = []
        current_hunk = None
        old_line_num = 0
        new_line_num = 0
        
        for line in diff_lines:
            if line.startswith('@@'):
                # Novo hunk header
                if current_hunk:
                    hunks.append(current_hunk)
                
                # Parse @@ -old_start,old_count +new_start,new_count @@
                import re
                match = re.match(r'^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@(.*)$', line)
                if match:
                    old_line_num = int(match.group(1))
                    new_line_num = int(match.group(2))
                    context = match.group(3).strip()
                else:
                    old_line_num = 1
                    new_line_num = 1
                    context = ''
                
                current_hunk = {
                    'header': line,
                    'context': context,
                    'lines': []
                }
            elif line.startswith('---') or line.startswith('+++'):
                # File headers - skip
                continue
            elif current_hunk is not None:
                if line.startswith('+'):
                    current_hunk['lines'].append({
                        'type': 'add',
                        'old_num': None,
                        'new_num': new_line_num,
                        'content': html.escape(line[1:])
                    })
                    new_line_num += 1
                elif line.startswith('-'):
                    current_hunk['lines'].append({
                        'type': 'remove',
                        'old_num': old_line_num,
                        'new_num': None,
                        'content': html.escape(line[1:])
                    })
                    old_line_num += 1
                else:
                    # Context line (starts with space or nothing)
                    content = line[1:] if line.startswith(' ') else line
                    current_hunk['lines'].append({
                        'type': 'context',
                        'old_num': old_line_num,
                        'new_num': new_line_num,
                        'content': html.escape(content)
                    })
                    old_line_num += 1
                    new_line_num += 1
        
        if current_hunk:
            hunks.append(current_hunk)
        
        return hunks

    @staticmethod
    def get_device_backups_for_compare(db: Session, device_id: str, limit: int = 20) -> List[Backup]:
        """Retorna os últimos backups de um dispositivo para seleção de comparação."""
        from sqlalchemy import desc
        import uuid
        
        try:
            device_uuid = uuid.UUID(device_id)
        except ValueError:
            return []
        
        # Busca um volume maior e filtra por arquivo existente no storage atual.
        candidates = db.query(Backup).filter(
            Backup.device_id == device_uuid,
            Backup.file_path.isnot(None),
            Backup.status == BackupStatus.SUCCESS,
        ).order_by(desc(Backup.created_at)).limit(max(limit * 5, 100)).all()

        valid = []
        for backup in candidates:
            resolved = DiffService.resolve_backup_path(backup)
            if resolved and os.path.exists(resolved):
                valid.append(backup)
                if len(valid) >= limit:
                    break
        return valid
