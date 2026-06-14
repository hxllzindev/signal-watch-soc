# Política de segurança

## Relato responsável

Não abra uma issue pública com credenciais, dados pessoais ou detalhes exploráveis. Envie um relato privado ao mantenedor com impacto, passos de reprodução e versão afetada.

## Controles implementados

- CSP restritiva, proteção contra framing, MIME sniffing e vazamento de referrer.
- Limite de 2 MiB por requisição e 1.000 eventos por lote.
- Validação de fontes, timestamps, estados, severidades e limites de regras.
- Autorização por papel em todas as operações de escrita.
- Escape de dados antes da renderização no navegador.
- Container executado como usuário sem privilégios, sem capabilities e com filesystem somente leitura.
- CodeQL, Semgrep, Gitleaks, Trivy e geração de SBOM no CI.

## Modelo de demonstração

O header `X-SOC-Role` implementa papéis de demonstração e não representa autenticação. Uma implantação real deve usar OIDC/OAuth 2.0, sessões assinadas, autorização centralizada e armazenamento persistente da auditoria.
