---
trigger: always_on
---

# Development Environment
## Target Architecture:
- ARM64 (aarch64)
## Framework:
- KernelPatch Module (KPM) by bmax121
### Restrictions:
- NÃO utilize a estrutura clássica de um LKM (Loadable Kernel Module). Este projeto NÃO gera um arquivo .ko padrão.
- O código final deve ser compilado para o formato aceito pelo KernelPatch (.kpm).
- Não dependa de headers completos de árvores de kernel locais de versões especificas (O KernelPatch é um patch que tenta ser compativel entre varias versões).

# Critical Differences KPM vs LKM
1. Resolução de Símbolos: KPM conta com o KernelPatch para resolver símbolos dinamicamente em runtime através de tabelas internas de kallsyms modificadas. Não use rotinas de exportação tradicionais EXPORT_SYMBOL.
2. Hooking Nativo: Use preferencialmente as macros e APIs fornecidas pelo ecossistema KernelPatch para `inline-hook` e `syscall-table-hook` em vez de tentar reconstruir manipulações manuais de registradores WP/BP no ARM64.

# Code Generation Guidelines
Style
- C puro focado em Kernel Linux embarcado (Android 4.14 a 6.12).

Safety
- Sempre adicione verificações de ponteiro nulo (NULL pointer checks) em todas as varreduras de structs como `task_struct` e `mm_struct`, pois falhas aqui resultam em Kernel Panic instantâneo e reinicialização do dispositivo.