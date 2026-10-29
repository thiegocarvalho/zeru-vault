# Como contribuir com o Zeru Vault

🇧🇷 Português · [🇺🇸 English](CONTRIBUTING.en.md)

Obrigado pelo interesse em contribuir com o **Zeru Vault**!

## Padrões de código

1. **Código autoexplicativo:** mantenha identificadores, tipos, constantes (`constexpr`) e o fluxo de controle claros e autoexplicativos, sem comentários no meio do código.
2. **Segurança de memória e zeroização:**
   - Nunca coloque material de chave em texto claro no heap. (Blobs cifrados e dados públicos podem usá-lo.)
   - Sempre zere os buffers temporários (`seed`, `kek`, `dek`, `pin`, escalares privados, chaves HMAC) com `sodium_memzero()` em todos os caminhos de retorno.
   - Use comparação em tempo constante (`sodium_memcmp` ou `mbedtls_ct_memcmp`) ao verificar MACs, tags ou segredos.
3. **Sem dependências no computador:** o `agent/ssh_vault_agent.py` precisa rodar em Python 3 usando só a biblioteca padrão.
4. **Avisos contam como erro na revisão:** o `make build` compila com `--warnings all`; mantenha zero avisos nos arquivos do projeto.

## Compilando e verificando

```bash
make build                                             # compila o firmware
make flash                                             # salva a NVS e grava só o app (segure BOOT e toque RST quando pedir)
make test                                              # assinatura SSH de ponta a ponta no dispositivo
python3 -I agent/ssh_vault_agent.py test --hostbound   # também testa a exibição da chave do servidor
make screenshots                                       # regenera docs/images/*.png a partir do código da interface
```

Nunca grave o `build/firmware.ino.merged.bin` num dispositivo que tenha um cofre: ele cobre a flash inteira, inclusive a partição NVS, e apaga todas as chaves.

Toda mudança em `firmware/ui.cpp` deve ser seguida de `make screenshots`; revise as imagens e inclua-as no mesmo commit, para o README sempre corresponder ao firmware.

## Documentação

A documentação principal é em **português (PT-BR)**; o inglês é a segunda língua (arquivos `*.en.md`). Ao mudar um documento, atualize as duas versões. A interface do dispositivo e o código continuam em inglês.

## Licenças

O código do projeto é MIT. Antes de adicionar uma dependência, fonte ou imagem, confira a licença e registre-a no [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md) (e na versão em inglês). Prefira licenças permissivas (MIT, BSD, Apache-2.0, ISC, SIL OFL para fontes).

## Invariantes de segurança

As mudanças precisam manter estas propriedades:

- Nada recebido do computador pode reiniciar o prazo do bloqueio automático, adiar o bloqueio ou aprovar um pedido.
- Telas de aprovação começam com *Reject* selecionado, ignoram os botões por `SIGN_ARM_MS`, descartam gestos iniciados antes do pedido e nunca usam repetição automática.
- As flags FIDO2 `UP`/`UV` precisam refletir o que de fato aconteceu no dispositivo.
- O protocolo serial só assina dados aceitos por `sshParseUserauth()` para a chave ativa.
- Tudo o que apaga segredos precisa chamar `compact()`, para que os dados cifrados antigos sejam apagados fisicamente.
- O reinício automático no bootloader pela USB CDC continua desativado (`Serial.enableReboot(false)`).
