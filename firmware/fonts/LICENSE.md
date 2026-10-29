# Fonts / Fontes

[Português](#português) · [English](#english)

---

## Português

Os arquivos `FreeSans9pt7b.h`, `FreeSansBold9pt7b.h`, `FreeSansBold12pt7b.h`, `FreeSansBold18pt7b.h` e `FreeMonoBold12pt7b.h` são **conversões em bitmap de fontes da [GNU FreeFont](https://www.gnu.org/software/freefont/)**, geradas com a ferramenta `fontconvert` da [Adafruit GFX Library](https://github.com/adafruit/Adafruit-GFX-Library).

| Parte | Origem | Licença |
| :--- | :--- | :--- |
| Desenho dos glifos (FreeSans, FreeMono) | GNU FreeFont | **GPL-3.0-or-later**, com a [exceção para fontes](https://www.gnu.org/software/freefont/license.html) |
| Formato `GFXfont` e ferramenta `fontconvert` | Adafruit Industries | BSD (texto abaixo) |

**O que isso significa para este projeto:**

- O código-fonte do Zeru Vault continua sob a licença MIT; estes arquivos de fonte continuam sob a licença deles.
- A exceção da FreeFont foi escrita para *documentos* (por exemplo, um PDF). Ela não cobre claramente programas, e o mantenedor da FreeFont já afirmou que distribuir a fonte dentro de um aplicativo coloca o aplicativo sob a GPL. Por isso, **trate o firmware compilado (`.bin`) que inclui estas fontes como distribuído sob a GPL-3.0-or-later**: quem distribuir o binário deve disponibilizar o código-fonte correspondente (este repositório) e o texto da GPL.
- Para eliminar essa obrigação, substitua estas fontes por fontes com licença permissiva (por exemplo SIL OFL, Apache-2.0 ou Bitstream Vera/DejaVu), convertidas com o `fontconvert`.

Isto é uma descrição de boa-fé, não aconselhamento jurídico.

## English

`FreeSans9pt7b.h`, `FreeSansBold9pt7b.h`, `FreeSansBold12pt7b.h`, `FreeSansBold18pt7b.h` and `FreeMonoBold12pt7b.h` are **bitmap conversions of [GNU FreeFont](https://www.gnu.org/software/freefont/) faces**, produced with the `fontconvert` tool of the [Adafruit GFX Library](https://github.com/adafruit/Adafruit-GFX-Library).

| Part | Origin | License |
| :--- | :--- | :--- |
| Glyph design (FreeSans, FreeMono) | GNU FreeFont | **GPL-3.0-or-later**, with the [font exception](https://www.gnu.org/software/freefont/license.html) |
| `GFXfont` format and `fontconvert` tool | Adafruit Industries | BSD (text below) |

**What this means for this project:**

- Zeru Vault's source code stays under the MIT license; these font files keep their own license.
- The FreeFont exception is written for *documents* (e.g. a PDF). It does not clearly cover programs, and the FreeFont maintainer has stated that shipping the font inside an application brings the application under the GPL. Therefore, **treat a compiled firmware image (`.bin`) that contains these fonts as distributed under GPL-3.0-or-later**: whoever distributes the binary must make the corresponding source (this repository) and the GPL text available.
- To remove that obligation, replace these fonts with permissively licensed ones (e.g. SIL OFL, Apache-2.0 or Bitstream Vera/DejaVu) converted with `fontconvert`.

This is a good-faith description, not legal advice.

---

## Adafruit GFX Library license (BSD)

```text
Software License Agreement (BSD License)

Copyright (c) 2012 Adafruit Industries.  All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.
```
