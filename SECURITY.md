# Política de Segurança

🇧🇷 Português · [🇺🇸 English](SECURITY.en.md)

## Modelo de ameaças

O **Zeru Vault** é uma chave de segurança física de código aberto (FIDO2/CTAP2 + agente SSH) para o ESP32-S3, com tela e dois botões físicos.

| Atacante | Objetivo | Defesa |
| :--- | :--- | :--- |
| Malware no computador (mesmo usuário) | Assinaturas / logins silenciosos | Toda assinatura exige que o usuário saia do *Reject* pré-selecionado para *Approve* e confirme com os dois botões, numa tela que mostra o site / usuário SSH / chave do servidor. Asserções com `up:false` recebem as **flags UP e UV zeradas**. |
| Malware no computador | Manter o cofre aberto para sempre | O bloqueio automático conta **apenas atividade nos botões físicos** (15 min), com limite fixo de 12 h por sessão. Tráfego do computador nunca reinicia esse prazo, e um pedido pendente não o adia. |
| Malware no computador | Gravar um firmware adulterado pela USB | O reinício automático pela USB CDC (toque de 1200 bps / sequência DTR-RTS) está **desativado**; entrar no modo de gravação exige o botão BOOT. |
| Malware no computador | Conseguir aprovação com um pedido bem cronometrado | A aprovação só é armada 700 ms depois de o pedido aparecer, gestos iniciados antes são descartados, *Reject* vem pré-selecionado e a repetição automática dos botões fica desligada nas telas de aprovação e de exclusão. |
| Site ou servidor SSH malicioso | Enganar o usuário para que aprove | O tipo de pedido vem do protocolo, nunca é deduzido do texto. RP IDs longos são cortados pela esquerda, para o domínio registrável continuar visível. Pedidos SSH "hostbound" mostram a impressão digital da chave do servidor. |
| Alguém olhando por cima do ombro / câmera | Descobrir o PIN pelos toques nos botões | O tambor do PIN começa num dígito aleatório a cada dígito digitado. |
| Ladrão com o dispositivo (sem o PIN) | Adivinhar o PIN | 10 tentativas, espera exponencial a partir da 3ª, contador gravado **antes** da derivação da chave (falha fechada se a gravação falhar) e apagamento completo da flash na 10ª falha. |
| Ladrão que copia a memória flash SPI | Força bruta offline no PIN | A chave que protege o cofre é `HMAC_eFuse(PBKDF2(PIN))`. A chave HMAC fica num bloco de eFuse protegido contra leitura, que só o periférico HMAC do próprio chip consegue usar; uma cópia da flash sozinha é inútil. |

### Riscos residuais (sendo explícitos)

- **Sem Secure Boot / Flash Encryption por padrão.** Um atacante com acesso físico *e* tempo pode entrar no modo de gravação com o botão BOOT, gravar o próprio firmware e usar o periférico HMAC do chip para tentar adivinhar o PIN **no próprio dispositivo**, contornando o contador de tentativas. O PBKDF2 calibrado (~0,9 s por tentativa) faz um PIN de 6 dígitos custar ~10 dias e um de 8 dígitos ~3 anos de ataque contínuo. Use 8 dígitos para chaves de alto valor, ou aplique o endurecimento opcional abaixo.
- **Sem backup.** As chaves são geradas no chip e nunca podem ser exportadas. Registre um segundo autenticador (ou guarde códigos de recuperação) em cada conta.
- **A verificação de usuário embutida é por sessão.** A flag FIDO2 `UV` significa "o PIN foi digitado no dispositivo nesta sessão" (no máximo 12 h, bloqueio após 15 min sem apertar botão), como em outros autenticadores com PIN digitado no próprio aparelho. Não há CTAP `clientPIN`.
- **O reset de fábrica não pede PIN.** Qualquer pessoa com o dispositivo na mão pode apagá-lo (só negação de serviço; nenhum dado é revelado). Isso segue o comportamento do reset FIDO das chaves comerciais.
- **USB VID/PID** `303a:1001` é o identificador de desenvolvimento da Espressif, e o número de série USB é o MAC do chip (um identificador fixo). Unidades de produção devem usar um PID próprio.

## Arquitetura criptográfica (formato do cofre v3)

1. **Chave de cifragem de dados (DEK).** Uma DEK aleatória de 256 bits cifra cada semente SSH e cada registro de passkey com AES-256-GCM (IV aleatório de 96 bits; AAD = versão do formato + slot/índice + nome da chave + chave pública).
2. **Proteção pelo PIN.** `KEK = HMAC_eFuse("ZV3/KEK" ‖ salt ‖ PBKDF2-HMAC-SHA256(PIN, salt, N))`, com `N` calibrado no chip para ~0,9 s (limitado a 20 000 – 1 000 000 e validado a cada desbloqueio). A DEK é cifrada com AES-256-GCM sob a KEK; a tag GCM serve de verificador do PIN. Salt, `N`, a indicação de hardware e a DEK cifrada ficam num único blob da NVS, então a troca de PIN é atômica.
3. **Vínculo com o hardware.** Na primeira configuração (ou no primeiro desbloqueio após atualizar da v2), o firmware grava uma chave aleatória de 256 bits num bloco de chave livre dos eFuses, com finalidade `HMAC_UP` e proteção contra leitura. Isso é **irreversível** e usa um dos seis blocos de chave; a placa continua utilizável em outros projetos.
4. **Apagamento seguro.** Apagar uma chave ou passkey, trocar o PIN, redefinir as passkeys ou migrar da v2 regrava toda a partição NVS por meio de uma cópia temporária resistente a queda de energia, guardada por instantes na partição FAT (que não é usada), apagando fisicamente os dados cifrados antigos. O reset de fábrica apaga a partição NVS e a área da cópia temporária.
5. **Credenciais FIDO2.** Os IDs de credencial são `nonce ‖ HMAC(semente, época ‖ rpIdHash ‖ nonce)`, verificados em tempo constante antes de qualquer pedido de aprovação. As chaves são derivadas por site a partir da semente do slot ativo (`ES256` ou `EdDSA`, respeitando a ordem de preferência do site). Credenciais detectáveis são guardadas **apenas** quando `rk=true`, cifradas sob a DEK. O `authenticatorReset` e o *Settings → Reset passkeys* trocam a época, revogando todas as credenciais. Os IDs de canal CTAPHID são aleatórios.
6. **SSH (sem oráculo de assinatura).** A interface serial só assina blocos RFC 4252 `SSH_MSG_USERAUTH_REQUEST` bem formados (ou `publickey-hostbound-v00@openssh.com`) para `ssh-ed25519` que correspondam à chave ativa.

## Endurecimento opcional: Secure Boot v2 + Flash Encryption

O build padrão **não** ativa esses recursos, de propósito: ambos são decisões permanentes gravadas nos eFuses do chip (bits programáveis uma única vez, que nunca podem ser apagados). Eles estão documentados aqui como opção futura para um dispositivo dedicado, "de produção".

| Recurso | O que é gravado | O que muda depois | Principal risco |
| :--- | :--- | :--- | :--- |
| **Secure Boot v2** | O resumo (digest) da(s) **sua(s)** chave(s) pública(s) de assinatura RSA-3072 (o ESP32-S3 só suporta RSA-PSS) e o bit de ativação | A ROM só inicia um bootloader assinado por você, e o bootloader só executa firmware assinado por você. Você continua podendo gravar qualquer coisa (até outro projeto) **desde que assine**. | **Perder a chave privada de assinatura** significa que a placa nunca mais roda firmware novo. O chip aceita até 3 resumos de chave; mantenha uma chave reserva e um backup. |
| **Flash Encryption (modo release)** | Uma chave AES-XTS gerada pelo chip, que ninguém consegue ler, e o contador de ativação | O conteúdo da flash fica cifrado com uma chave única do chip; a gravação serial comum é recusada. Atualizações passam pelo caminho assinado / OTA. | Uma queda de energia no **primeiro** boot (quando a flash é cifrada no lugar) ou um firmware sem caminho de atualização pode deixar a placa inutilizável. |
| `DIS_USB_JTAG`, `DIS_PAD_JTAG`, `ENABLE_SECURITY_DOWNLOAD` (ou `DIS_DOWNLOAD_MODE`) | Desativam as portas de depuração e restringem / desativam o modo de gravação da ROM | Sem depuração JTAG; o esptool não consegue mais ler a flash (ou nem conectar). | O desenvolvimento fica muito mais difícil; erros não podem ser desfeitos. |

Com tudo isso ativo, a força bruta do PIN no chip descrita em *Riscos residuais* deixa de ser possível, porque o atacante não consegue executar o próprio código no chip.

Requisitos e recomendações:

1. O núcleo Arduino traz um bootloader pré-compilado sem suporte a Secure Boot, então o firmware precisa ser compilado com o **ESP-IDF** (Arduino como componente do ESP-IDF), com `CONFIG_SECURE_BOOT_V2_ENABLED`, `CONFIG_SECURE_FLASH_ENC_ENABLED` (modo release) e a cifragem da NVS (esquema baseado em HMAC) ativados.
2. Gere a chave de assinatura offline, guarde-a com backup (por exemplo, num gerenciador de senhas) e mantenha pelo menos um resumo de chave reserva revogável.
3. Ensaie o procedimento inteiro antes numa **segunda placa, reserva**. Mantenha essa reserva como placa de desenvolvimento.
4. Use mesmo assim um PIN de 8 dígitos.

## Como reportar uma vulnerabilidade

Por favor, **não** abra uma issue pública no GitHub para vulnerabilidades de segurança. Reporte de forma privada pela aba de Security Advisories do repositório (`Security` -> `Report a vulnerability`), informando:

- Componente afetado (`firmware/vault.cpp`, `firmware/fido2.cpp`, `firmware/sshparse.cpp`, `agent/ssh_vault_agent.py` etc.)
- Passos de prova de conceito ou payload para reproduzir
- Avaliação de impacto
