"""
Custom HTML documentation for the external Backup Center API.
"""

from textwrap import dedent


API_DOCUMENTATION_HTML = dedent(
    """
    <!DOCTYPE html>
    <html lang="pt-BR">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Backup Center External API | API Externa do Backup Center</title>
        <style>
            :root {
                --bg: #f4f7fb;
                --panel: #ffffff;
                --panel-soft: #f8fbff;
                --text: #0f172a;
                --muted: #52607a;
                --line: #d9e2ec;
                --accent: #0f766e;
                --accent-soft: #dff7f4;
                --accent-strong: #0b5d57;
                --code-bg: #0f172a;
                --code-line: #1e293b;
                --code-text: #dbe7ff;
                --shadow: 0 20px 50px rgba(15, 23, 42, 0.08);
                --radius: 22px;
                --sidebar-width: 280px;
                --mono: "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace;
                --sans: Inter, ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
            }

            * {
                box-sizing: border-box;
            }

            html {
                scroll-behavior: smooth;
            }

            body {
                margin: 0;
                font-family: var(--sans);
                background: linear-gradient(180deg, #f8fbff 0%, #eef4fb 100%);
                color: var(--text);
            }

            a {
                color: inherit;
                text-decoration: none;
            }

            code,
            pre {
                font-family: var(--mono);
            }

            .layout {
                min-height: 100vh;
                display: flex;
            }

            .sidebar {
                width: var(--sidebar-width);
                flex-shrink: 0;
                background: rgba(255, 255, 255, 0.92);
                border-right: 1px solid var(--line);
                backdrop-filter: blur(10px);
                position: sticky;
                top: 0;
                height: 100vh;
                overflow: hidden;
            }

            .sidebar-inner {
                height: 100%;
                display: flex;
                flex-direction: column;
            }

            .brand {
                padding: 28px 24px 22px;
                border-bottom: 1px solid var(--line);
            }

            .brand-row {
                display: flex;
                gap: 14px;
                align-items: center;
            }

            .brand-icon {
                width: 52px;
                height: 52px;
                border-radius: 16px;
                display: grid;
                place-items: center;
                background: linear-gradient(135deg, var(--accent) 0%, #14b8a6 100%);
                color: #fff;
                box-shadow: var(--shadow);
                flex-shrink: 0;
            }

            .brand-title {
                margin: 0;
                font-size: 20px;
                line-height: 1.1;
                font-weight: 700;
            }

            .brand-subtitle {
                margin: 4px 0 0;
                color: var(--muted);
                font-size: 13px;
            }

            .base-url {
                margin-top: 18px;
                padding: 14px 16px;
                border: 1px solid #b7ece6;
                background: #ecfdf9;
                border-radius: 16px;
            }

            .base-url strong {
                display: block;
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 0.08em;
                margin-bottom: 6px;
                color: var(--accent-strong);
            }

            .base-url code {
                display: block;
                font-size: 12px;
                line-height: 1.5;
                color: var(--accent-strong);
                word-break: break-word;
            }

            .sidebar-search {
                padding: 18px 20px 10px;
            }

            .sidebar-search input {
                width: 100%;
                border: 1px solid var(--line);
                border-radius: 14px;
                padding: 12px 14px;
                font: inherit;
                font-size: 14px;
                color: var(--text);
                background: #fff;
                outline: none;
            }

            .sidebar-search input:focus {
                border-color: #67d3c8;
                box-shadow: 0 0 0 4px rgba(20, 184, 166, 0.12);
            }

            .nav {
                overflow: auto;
                padding: 8px 16px 24px;
            }

            .nav-group + .nav-group {
                margin-top: 24px;
            }

            .nav-label {
                margin: 0 10px 10px;
                color: var(--muted);
                font-size: 11px;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.12em;
            }

            .nav-link {
                display: block;
                padding: 11px 12px;
                border-radius: 14px;
                border: 1px solid transparent;
                color: var(--muted);
                font-size: 14px;
                margin-bottom: 4px;
            }

            .nav-link:hover {
                background: #fff;
                color: var(--text);
                border-color: var(--line);
            }

            .nav-link.active {
                color: var(--accent-strong);
                background: var(--accent-soft);
                border-color: #9de7de;
                font-weight: 600;
            }

            .content {
                min-width: 0;
                flex: 1;
                padding: 30px;
            }

            .wrap {
                max-width: 1320px;
                margin: 0 auto;
            }

            .hero {
                display: grid;
                grid-template-columns: minmax(0, 1.15fr) minmax(340px, 0.85fr);
                overflow: hidden;
                background: var(--panel);
                border: 1px solid var(--line);
                border-radius: 28px;
                box-shadow: var(--shadow);
            }

            .hero-copy {
                padding: 48px;
            }

            .eyebrow {
                display: inline-flex;
                align-items: center;
                padding: 7px 12px;
                border-radius: 999px;
                background: var(--accent-soft);
                color: var(--accent-strong);
                font-size: 11px;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.12em;
            }

            .hero h1,
            .section-copy h2 {
                margin: 18px 0 0;
                font-size: 44px;
                line-height: 1.08;
                letter-spacing: 0;
            }

            .hero p,
            .section-copy p {
                margin: 18px 0 0;
                color: var(--muted);
                line-height: 1.8;
                font-size: 16px;
            }

            .hero-grid {
                display: grid;
                grid-template-columns: repeat(3, minmax(0, 1fr));
                gap: 14px;
                margin-top: 28px;
            }

            .stat {
                border: 1px solid var(--line);
                background: var(--panel-soft);
                border-radius: 18px;
                padding: 18px;
            }

            .stat strong {
                display: block;
                font-size: 14px;
                margin-bottom: 6px;
            }

            .stat span {
                display: block;
                color: var(--muted);
                font-size: 13px;
                line-height: 1.6;
            }

            .code-panel {
                background: var(--code-bg);
                color: var(--code-text);
                border-left: 1px solid #1f314a;
                padding: 28px;
            }

            .panel-head {
                display: flex;
                align-items: center;
                justify-content: space-between;
                gap: 12px;
                margin-bottom: 12px;
            }

            .panel-head span {
                font-size: 11px;
                font-weight: 700;
                letter-spacing: 0.12em;
                text-transform: uppercase;
                color: #8fa3c4;
            }

            .copy-btn {
                border: 1px solid #31425f;
                background: transparent;
                color: #dbe7ff;
                border-radius: 10px;
                font: inherit;
                font-size: 12px;
                padding: 7px 10px;
                cursor: pointer;
            }

            .copy-btn:hover {
                border-color: #5072a5;
                background: rgba(255, 255, 255, 0.04);
            }

            pre {
                margin: 0;
                white-space: pre;
                overflow: auto;
                background: rgba(2, 6, 23, 0.38);
                border: 1px solid #21314c;
                border-radius: 18px;
                padding: 18px;
                font-size: 13px;
                line-height: 1.7;
            }

            .sections {
                margin-top: 28px;
                display: grid;
                gap: 24px;
            }

            .doc-section {
                display: grid;
                grid-template-columns: minmax(0, 1.02fr) minmax(340px, 0.98fr);
                gap: 0;
                background: var(--panel);
                border: 1px solid var(--line);
                border-radius: 28px;
                overflow: hidden;
                box-shadow: var(--shadow);
            }

            .section-copy {
                padding: 36px 40px;
            }

            .method-row {
                display: flex;
                flex-wrap: wrap;
                align-items: center;
                gap: 12px;
            }

            .method {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                border-radius: 999px;
                padding: 7px 12px;
                background: #e0f2fe;
                color: #075985;
                font-size: 11px;
                font-weight: 700;
                text-transform: uppercase;
                letter-spacing: 0.12em;
            }

            .path {
                display: inline-block;
                max-width: 100%;
                overflow-wrap: anywhere;
                border-radius: 999px;
                background: #f1f5f9;
                padding: 8px 12px;
                font-size: 14px;
                color: var(--text);
            }

            .callout {
                margin-top: 24px;
                border: 1px solid #f6d389;
                background: #fff8e6;
                color: #854d0e;
                border-radius: 18px;
                padding: 18px;
                line-height: 1.75;
                font-size: 14px;
            }

            .callout strong {
                display: block;
                margin-bottom: 6px;
            }

            .mini-grid {
                display: grid;
                grid-template-columns: repeat(2, minmax(0, 1fr));
                gap: 14px;
                margin-top: 24px;
            }

            .mini-card,
            .table-wrap {
                border: 1px solid var(--line);
                background: var(--panel-soft);
                border-radius: 18px;
            }

            .mini-card {
                padding: 18px;
            }

            .mini-card strong {
                display: block;
                font-size: 14px;
            }

            .mini-card p {
                margin: 8px 0 0;
                color: var(--muted);
                font-size: 14px;
                line-height: 1.7;
            }

            .inline-code {
                display: inline-block;
                border-radius: 8px;
                background: #fff;
                border: 1px solid var(--line);
                padding: 2px 7px;
                font-size: 12px;
                color: var(--text);
            }

            table {
                width: 100%;
                border-collapse: collapse;
                font-size: 14px;
            }

            th,
            td {
                text-align: left;
                vertical-align: top;
                padding: 16px 18px;
                border-bottom: 1px solid var(--line);
            }

            th {
                color: var(--muted);
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 0.08em;
                background: rgba(255, 255, 255, 0.55);
            }

            tr:last-child td {
                border-bottom: 0;
            }

            .token-keyword { color: #f9a8d4; }
            .token-string { color: #93c5fd; }
            .token-number { color: #fcd34d; }
            .token-comment { color: #64748b; }
            .token-property { color: #5eead4; }
            .token-function { color: #c4b5fd; }
            .token-operator { color: #e2e8f0; }

            .hidden-by-search {
                display: none !important;
            }

            @media (max-width: 1180px) {
                .hero,
                .doc-section {
                    grid-template-columns: 1fr;
                }

                .code-panel {
                    border-left: 0;
                    border-top: 1px solid #1f314a;
                }
            }

            @media (max-width: 960px) {
                .layout {
                    display: block;
                }

                .sidebar {
                    position: static;
                    width: 100%;
                    height: auto;
                    border-right: 0;
                    border-bottom: 1px solid var(--line);
                }

                .content {
                    padding: 18px;
                }
            }

            @media (max-width: 720px) {
                .hero-copy,
                .section-copy,
                .code-panel {
                    padding: 24px;
                }

                .hero h1,
                .section-copy h2 {
                    font-size: 32px;
                }

                .hero-grid,
                .mini-grid {
                    grid-template-columns: 1fr;
                }

                .path {
                    border-radius: 16px;
                }
            }
        </style>
    </head>
    <body>
        <div class="layout">
            <aside class="sidebar">
                <div class="sidebar-inner">
                    <div class="brand">
                        <div class="brand-row">
                            <div class="brand-icon" aria-hidden="true">
                                <svg xmlns="http://www.w3.org/2000/svg" width="28" height="28" viewBox="0 0 24 24" fill="currentColor">
                                    <path d="M5 4a3 3 0 0 0-3 3v10a3 3 0 0 0 3 3h14a3 3 0 0 0 3-3V7a3 3 0 0 0-3-3H5Zm0 2h14a1 1 0 0 1 1 1v1H4V7a1 1 0 0 1 1-1Zm-1 4h16v7a1 1 0 0 1-1 1H5a1 1 0 0 1-1-1v-7Zm3 2a1 1 0 1 0 0 2h4a1 1 0 1 0 0-2H7Zm0 4a1 1 0 1 0 0 2h7a1 1 0 1 0 0-2H7Z"/>
                                </svg>
                            </div>
                            <div>
                                <p class="brand-title">Backup Center API</p>
                                <p class="brand-subtitle">Referência de integração externa</p>
                            </div>
                        </div>
                        <div class="base-url">
                            <strong>URL base</strong>
                            <code>https://backupcenter.ajustconsulting.com.br</code>
                        </div>
                    </div>

                    <div class="sidebar-search">
                        <input id="doc-search" type="text" placeholder="Buscar seções">
                    </div>

                    <nav class="nav" id="doc-nav">
                        <div class="nav-group">
                            <p class="nav-label">Primeiros passos</p>
                            <a href="#overview" class="nav-link">Visão geral</a>
                            <a href="#auth" class="nav-link">Autenticação</a>
                        </div>
                        <div class="nav-group">
                            <p class="nav-label">Endpoints</p>
                            <a href="#list-groups" class="nav-link">Listar grupos</a>
                            <a href="#list-backups" class="nav-link">Listar backups</a>
                            <a href="#download-backup" class="nav-link">Baixar backup</a>
                        </div>
                    </nav>
                </div>
            </aside>

            <main class="content">
                <div class="wrap">
                    <section id="overview" class="hero" data-doc-section="overview backup center api external integration groups backups downloads stable access">
                        <div class="hero-copy">
                            <span class="eyebrow">API externa</span>
                            <h1>Acesso estável a grupos, backups e downloads.</h1>
                            <p>
                                Esta API expõe apenas o mínimo necessário para integrações: listar grupos, listar backups de um grupo e baixar um arquivo de backup.
                                Apenas dispositivos cujo último status de backup está como sucesso são expostos. Detalhes sensíveis de rede não são expostos.
                            </p>
                            <div class="hero-grid">
                                <div class="stat">
                                    <strong>3 endpoints</strong>
                                    <span>Superfície enxuta para automação e integração.</span>
                                </div>
                                <div class="stat">
                                    <strong>Autenticação Bearer</strong>
                                    <span>Use um token de API do Backup Center no cabeçalho.</span>
                                </div>
                                <div class="stat">
                                    <strong>Identificadores imutáveis</strong>
                                    <span>Use <code class="inline-code">device_id</code> e o <code class="inline-code">id</code> do backup.</span>
                                </div>
                            </div>
                        </div>
                        <div class="code-panel">
                            <div class="panel-head">
                                <span>Exemplo rápido</span>
                                <button class="copy-btn" data-copy-target="code-overview">Copiar</button>
                            </div>
                            <pre id="code-overview"><code><span class="token-comment"># 1. Listar grupos</span>
<span class="token-keyword">curl</span> -H <span class="token-string">"Authorization: Bearer bc_your_token"</span> \\
  <span class="token-string">"https://backupcenter.ajustconsulting.com.br/api/v1/external/groups"</span>

<span class="token-comment"># 2. Listar backups de um grupo</span>
<span class="token-keyword">curl</span> -H <span class="token-string">"Authorization: Bearer bc_your_token"</span> \\
  <span class="token-string">"https://backupcenter.ajustconsulting.com.br/api/v1/external/groups/GROUP_ID/backups"</span>

<span class="token-comment"># 3. Baixar um arquivo de backup</span>
<span class="token-keyword">curl</span> -H <span class="token-string">"Authorization: Bearer bc_your_token"</span> \\
  <span class="token-string">"https://backupcenter.ajustconsulting.com.br/api/v1/external/backups/BACKUP_ID/download"</span> \\
  -o <span class="token-string">backup.bin</span></code></pre>
                        </div>
                    </section>

                    <div class="sections">
                        <section id="auth" class="doc-section" data-doc-section="authentication bearer token api token authorization header">
                            <div class="section-copy">
                                <span class="eyebrow">Autenticação</span>
                                <h2>Use um token de API do Backup Center.</h2>
                                <p>
                                    Gere o token dentro da plataforma e envie no cabeçalho <code class="inline-code">Authorization</code>.
                                    A API externa não usa o endpoint de login do tenant.
                                </p>
                                <div class="mini-card" style="margin-top: 24px;">
                                    <strong>Formato do cabeçalho</strong>
                                    <p><code class="inline-code">Authorization: Bearer bc_your_token_here</code></p>
                                </div>
                            </div>
                            <div class="code-panel">
                                <div class="panel-head">
                                    <span>Exemplo em Python</span>
                                    <button class="copy-btn" data-copy-target="code-auth">Copiar</button>
                                </div>
                                <pre id="code-auth"><code><span class="token-keyword">import</span> requests

base_url <span class="token-operator">=</span> <span class="token-string">"https://backupcenter.ajustconsulting.com.br"</span>
headers <span class="token-operator">=</span> {
    <span class="token-string">"Authorization"</span>: <span class="token-string">"Bearer bc_your_token_here"</span>
}

response <span class="token-operator">=</span> requests.<span class="token-function">get</span>(
    <span class="token-string">f"{base_url}/api/v1/external/groups"</span>,
    headers<span class="token-operator">=</span>headers,
)

<span class="token-function">print</span>(response.status_code)
<span class="token-function">print</span>(response.json())</code></pre>
                            </div>
                        </section>

                        <section id="list-groups" class="doc-section" data-doc-section="list groups external groups provider client group id device count">
                            <div class="section-copy">
                                <div class="method-row">
                                    <span class="method">GET</span>
                                    <code class="path">/api/v1/external/groups</code>
                                </div>
                                <h2>Listar grupos</h2>
                                <p>
                                    Retorna os grupos ativos disponíveis para o tenant autenticado.
                                    Use o <code class="inline-code">id</code> do grupo nesta resposta no endpoint de backups.
                                    O contador considera somente dispositivos não inativos cujo último backup está em sucesso.
                                </p>
                                <div class="table-wrap" style="margin-top: 24px;">
                                    <table>
                                        <thead>
                                            <tr>
                                                <th>Campo</th>
                                                <th>Significado</th>
                                            </tr>
                                        </thead>
                                        <tbody>
                                            <tr>
                                                <td><code>id</code></td>
                                                <td>UUID estável do grupo.</td>
                                            </tr>
                                            <tr>
                                                <td><code>name</code></td>
                                                <td>Nome exibido do grupo.</td>
                                            </tr>
                                            <tr>
                                                <td><code>device_count</code></td>
                                                <td>Número de dispositivos não inativos dentro do grupo com último backup em sucesso.</td>
                                            </tr>
                                            <tr>
                                                <td><code>last_backup_at</code></td>
                                                <td>Data/hora do último backup com sucesso do grupo.</td>
                                            </tr>
                                        </tbody>
                                    </table>
                                </div>
                            </div>
                            <div class="code-panel">
                                <div class="panel-head">
                                    <span>Exemplo de resposta</span>
                                    <button class="copy-btn" data-copy-target="code-groups">Copiar</button>
                                </div>
                                <pre id="code-groups"><code>{
  <span class="token-property">"total"</span>: <span class="token-number">2</span>,
  <span class="token-property">"groups"</span>: [
    {
      <span class="token-property">"id"</span>: <span class="token-string">"91d21c58-dc9c-4e39-b008-b6ff7aa7f53a"</span>,
      <span class="token-property">"name"</span>: <span class="token-string">"Flashnet"</span>,
      <span class="token-property">"device_count"</span>: <span class="token-number">10</span>,
      <span class="token-property">"last_backup_at"</span>: <span class="token-string">"2026-05-14T10:30:00Z"</span>
    },
    {
      <span class="token-property">"id"</span>: <span class="token-string">"89d15015-cb7c-482d-86f6-5adda8cdcf63"</span>,
      <span class="token-property">"name"</span>: <span class="token-string">"BVNET"</span>,
      <span class="token-property">"device_count"</span>: <span class="token-number">7</span>,
      <span class="token-property">"last_backup_at"</span>: <span class="token-string">"2026-05-13T18:06:27Z"</span>
    }
  ]
}</code></pre>
                            </div>
                        </section>

                        <section id="list-backups" class="doc-section" data-doc-section="list backups by group backup id device id immutable identifier status success">
                            <div class="section-copy">
                                <div class="method-row">
                                    <span class="method">GET</span>
                                    <code class="path">/api/v1/external/groups/{group_id}/backups</code>
                                </div>
                                <h2>Listar backups de um grupo</h2>
                                <p>
                                    Retorna os backups paginados do grupo selecionado, apenas para dispositivos cujo último status de backup está como sucesso. A resposta inclui
                                    <code class="inline-code">device_id</code> além de
                                    <code class="inline-code">device_name</code>.
                                    Use <code class="inline-code">device_id</code> como referência estável do dispositivo, porque nome e IP podem mudar.
                                </p>
                                <div class="callout">
                                    <strong>Por que o <code class="inline-code">device_id</code> importa</strong>
                                    Nome do dispositivo e IP são campos operacionais mutáveis.
                                    <code class="inline-code">device_id</code> é imutável e é o campo correto para correlacionar backups com segurança ao longo do tempo.
                                </div>
                                <div class="mini-grid">
                                    <div class="mini-card">
                                        <strong>Parâmetro de rota</strong>
                                        <p><code class="inline-code">group_id</code><br>UUID do grupo retornado pelo endpoint de grupos.</p>
                                    </div>
                                    <div class="mini-card">
                                        <strong>Parâmetros de consulta</strong>
                                        <p><code class="inline-code">page</code>, <code class="inline-code">per_page</code>, <code class="inline-code">status</code><br>O status padrão é <code class="inline-code">success</code>; dispositivos cujo último backup falhou não são expostos.</p>
                                    </div>
                                </div>
                            </div>
                            <div class="code-panel">
                                <div class="panel-head">
                                    <span>Exemplo de resposta</span>
                                    <button class="copy-btn" data-copy-target="code-backups">Copiar</button>
                                </div>
                                <pre id="code-backups"><code>{
  <span class="token-property">"group"</span>: <span class="token-string">"Flashnet"</span>,
  <span class="token-property">"page"</span>: <span class="token-number">1</span>,
  <span class="token-property">"per_page"</span>: <span class="token-number">50</span>,
  <span class="token-property">"total"</span>: <span class="token-number">1</span>,
  <span class="token-property">"pages"</span>: <span class="token-number">1</span>,
  <span class="token-property">"items"</span>: [
    {
      <span class="token-property">"id"</span>: <span class="token-string">"a1b2c3d4-e89b-12d3-a456-426614174000"</span>,
      <span class="token-property">"device_id"</span>: <span class="token-string">"bfa9d28a-4fc6-4dc4-9280-a2aad70feeb3"</span>,
      <span class="token-property">"device_name"</span>: <span class="token-string">"FLASHNET - ROUTER"</span>,
      <span class="token-property">"status"</span>: <span class="token-string">"success"</span>,
      <span class="token-property">"file_size_bytes"</span>: <span class="token-number">14002</span>,
      <span class="token-property">"hash_sha256"</span>: <span class="token-string">"0d59d0f8..."</span>,
      <span class="token-property">"created_at"</span>: <span class="token-string">"2026-05-14T10:30:00Z"</span>,
      <span class="token-property">"download_url"</span>: <span class="token-string">"/api/v1/external/backups/a1b2c3d4-e89b-12d3-a456-426614174000/download"</span>
    }
  ]
}</code></pre>
                            </div>
                        </section>

                        <section id="download-backup" class="doc-section" data-doc-section="download backup binary file backup id success status">
                            <div class="section-copy">
                                <div class="method-row">
                                    <span class="method">GET</span>
                                    <code class="path">/api/v1/external/backups/{backup_id}/download</code>
                                </div>
                                <h2>Baixar um arquivo de backup</h2>
                                <p>
                                    Baixa o arquivo binário de um backup de dispositivo cujo último status de backup continua em sucesso. Use o
                                    <code class="inline-code">id</code> retornado pelo endpoint de backups.
                                </p>
                                <div class="mini-card" style="margin-top: 24px;">
                                    <strong>Entrada obrigatória</strong>
                                    <p><code class="inline-code">backup_id</code><br>UUID do backup que você deseja baixar.</p>
                                </div>
                            </div>
                            <div class="code-panel">
                                <div class="panel-head">
                                    <span>Exemplo cURL</span>
                                    <button class="copy-btn" data-copy-target="code-download">Copiar</button>
                                </div>
                                <pre id="code-download"><code>curl -H <span class="token-string">"Authorization: Bearer bc_your_token"</span> \\
  <span class="token-string">"https://backupcenter.ajustconsulting.com.br/api/v1/external/backups/a1b2c3d4-e89b-12d3-a456-426614174000/download"</span> \\
  -o <span class="token-string">router_backup.bin</span></code></pre>
                            </div>
                        </section>
                    </div>
                </div>
            </main>
        </div>

        <script>
            const searchInput = document.getElementById("doc-search");
            const navLinks = Array.from(document.querySelectorAll(".nav-link"));
            const sections = Array.from(document.querySelectorAll("[data-doc-section]"));

            if (searchInput) {
                searchInput.addEventListener("input", () => {
                    const query = searchInput.value.trim().toLowerCase();
                    navLinks.forEach((link) => {
                        const targetId = link.getAttribute("href").replace("#", "");
                        const section = sections.find((item) => item.id === targetId);
                        const haystack = ((link.textContent || "") + " " + ((section && section.dataset.docSection) || "")).toLowerCase();
                        const visible = !query || haystack.includes(query);
                        link.classList.toggle("hidden-by-search", !visible);
                        if (section) {
                            section.classList.toggle("hidden-by-search", !visible);
                        }
                    });
                });
            }

            const observer = new IntersectionObserver((entries) => {
                entries.forEach((entry) => {
                    const link = navLinks.find((item) => item.getAttribute("href") === "#" + entry.target.id);
                    if (!link) {
                        return;
                    }
                    if (entry.isIntersecting) {
                        navLinks.forEach((item) => item.classList.remove("active"));
                        link.classList.add("active");
                    }
                });
            }, { rootMargin: "-28% 0px -55% 0px", threshold: 0.1 });

            sections.forEach((section) => observer.observe(section));

            document.querySelectorAll("[data-copy-target]").forEach((button) => {
                button.addEventListener("click", async () => {
                    const target = document.getElementById(button.dataset.copyTarget);
                    if (!target) {
                        return;
                    }
                    const original = button.textContent;
                    try {
                        await navigator.clipboard.writeText(target.innerText);
                        button.textContent = "Copied";
                    } catch (_error) {
                        button.textContent = "Failed";
                    }
                    setTimeout(() => {
                        button.textContent = original;
                    }, 1200);
                });
            });
        </script>
    </body>
    </html>
    """
).strip()
