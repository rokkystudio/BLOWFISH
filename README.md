# Blowfish

`Blowfish` — консольная Windows-программа для шифрования и расшифрования файлов
на локальной реализации `Blowfish`, без `Crypto++`, `OpenSSL`, `PBKDF2`,
`HMAC`, magic bytes и контейнерного формата.

Программа работает с `raw key`: ключ берется как есть из введенного текста.

Папка `sources/cryptopp` остается в репозитории, но в текущей реализации и
сборке не используется.

## Что умеет

- режимы `CBC`, `CFB`, `OFB`, `CTR`
- выбор режима через CLI
- выбор режима через Win32-окно из контекстного меню
- три схемы хранения `IV`: `prefix`, `suffix`, `manual`
- автоматическая генерация `IV`, если он не передан вручную
- raw-формат файла без сигнатур и служебных заголовков

По умолчанию:

- `mode = cbc`
- `iv-position = prefix`

## Формат данных

Размер блока Blowfish — `8` байт.

Поддерживаются три схемы хранения:

- `prefix`: `[IV][ciphertext]`
- `suffix`: `[ciphertext][IV]`
- `manual`: `[ciphertext]`, а `IV` задается отдельно

Программа намеренно не добавляет в файл:

- magic bytes
- заголовки формата
- метаданные о режиме шифрования
- проверку целостности
- `base64`

Из этого следует важное свойство: для расшифрования нужно знать тот же набор
параметров, что использовался при шифровании:

- ключ
- режим (`CBC` / `CFB` / `OFB` / `CTR`)
- способ хранения `IV`
- сам `IV`, если использовался `manual`

Если ключ, режим или `IV` неверны, программа не пытается это детектировать по
сигнатурам файла. На выходе получится неверно расшифрованный набор байтов.

## Поведение режимов

- `CBC` использует `PKCS#5/PKCS#7` padding при шифровании.
- `CFB`, `OFB` и `CTR` работают без padding.
- При расшифровании `CBC` программа пытается снять padding. Если padding не
  похож на корректный, данные возвращаются как есть, без ошибки формата. Это
  сделано специально, чтобы неправильный ключ не выдавал наличие служебной
  структуры файла.

## Использование из консоли

Базовое шифрование с настройками по умолчанию:

```powershell
.\Blowfish.exe --encrypt -i "C:\Data\file.txt" -o "C:\Data\file.bf" -k "16wmCCdPx7NOLG3"
```

`CBC` с `IV` в начале файла:

```powershell
.\Blowfish.exe --encrypt -i "C:\Data\bundle.json" -o "C:\Data\hide.dat" -k "16wmCCdPx7NOLG3" --mode cbc --iv-position prefix
```

`CFB` с `IV` в конце файла:

```powershell
.\Blowfish.exe --encrypt -i "C:\Data\file.txt" -o "C:\Data\file.cfb" -k "16wmCCdPx7NOLG3" --mode cfb --iv-position suffix
```

`OFB`:

```powershell
.\Blowfish.exe --encrypt -i "C:\Data\file.txt" -o "C:\Data\file.ofb" -k "16wmCCdPx7NOLG3" --mode ofb --iv-position prefix
```

`CTR`:

```powershell
.\Blowfish.exe --encrypt -i "C:\Data\file.txt" -o "C:\Data\file.ctr" -k "16wmCCdPx7NOLG3" --mode ctr --iv-position prefix
```

Расшифрование с ручным `IV`:

```powershell
.\Blowfish.exe --decrypt -i "C:\Data\file.bin" -o "C:\Data\file.txt" -k "16wmCCdPx7NOLG3" --mode cbc --iv-position manual --iv-hex 0011223344556677
```

## Параметры CLI

- `--encrypt`
- `--decrypt`
- `--input` / `-i`
- `--output` / `-o`
- `--key` / `-k`
- `--mode cbc|cfb|ofb|ctr`
- `--iv-position prefix|suffix|manual`
- `--iv-hex`
- `--force`
- `--help`

Если `--output` не задан:

- при шифровании добавляется `.bf`
- при расшифровании убирается `.bf`
- если расширения `.bf` нет, добавляется `.ubf`

## Контекстное меню

После сборки CMake публикует:

- `build\Blowfish.exe`
- `build\install.bat`
- `build\uninstall.bat`

Установка:

```powershell
.\build\install.bat
```

Удаление:

```powershell
.\build\uninstall.bat
```

При запуске из контекстного меню открывается окно, где можно задать:

- `raw key`
- `mode`: `CBC`, `CFB`, `OFB`, `CTR`
- `iv-position`: `prefix`, `suffix`, `manual`
- `IV hex`, если выбран `manual`

GUI не подставляет скрытую парольную модель и не записывает в файл служебную
сигнатуру режима.

## Сборка

Проект собирается на локальной реализации Blowfish из:

- `sources/blowfish.h`
- `sources/blowfish.cpp`

Текущая CMake-конфигурация линкует `bcrypt` только для генерации случайного
`IV` через системный RNG Windows.

## Ограничения

- Blowfish использует блок `64` бита и считается устаревшим алгоритмом.
- В формате нет проверки целостности.
- Для расшифрования нужно вручную знать режим и схему хранения `IV`.
- При неверном ключе, неверном режиме или неверном `IV` результатом будет
  неправильный набор байтов без надежного способа отличить его от корректного
  по самому файлу.
