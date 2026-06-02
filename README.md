# Blowfish

`Blowfish` — консольная Windows-программа для шифрования и расшифрования файлов
алгоритмом Blowfish с собственным локальным движком, без `Crypto++`, `OpenSSL`,
`PBKDF2` и парольной обвязки.

Программа работает только с raw key.

Папка `sources/cryptopp` остаётся в репозитории. Сейчас библиотека не участвует
в сборке и не нужна для текущей реализации, но её сохраняем на случай будущих
задач.

## Что умеет

- `CBC` и `CFB`
- `IV` в начале файла
- `IV` в конце файла
- `IV` вручную, без хранения в файле
- запуск из консоли
- запуск из контекстного меню Проводника

## Формат данных

Размер блока Blowfish — `8` байт.

Поддерживаются три схемы хранения:

- `prefix`: `[IV][ciphertext]`
- `suffix`: `[ciphertext][IV]`
- `manual`: `[ciphertext]`, а `IV` передаётся отдельно

Для `CBC` используется `PKCS#5/PKCS#7` padding.

Для `CFB` padding не используется.

Никаких специальных заголовков, `base64`, `HMAC`, `PBKDF2`, magic bytes или
форматных контейнеров программа не добавляет.

## Использование из консоли

Шифрование:

```powershell
.\Blowfish.exe --encrypt -i "C:\Data\file.txt" -o "C:\Data\file.bf" -k "16wmCCdPx7NOLG3"
```

Шифрование `CBC` с `IV` в начале файла:

```powershell
.\Blowfish.exe --encrypt -i "C:\Data\bundle.json" -o "C:\Data\hide.dat" -k "16wmCCdPx7NOLG3" --mode cbc --iv-position prefix
```

Расшифрование `CBC` с `IV` в конце файла:

```powershell
.\Blowfish.exe --decrypt -i "C:\Data\file.dat" -o "C:\Data\file.json" -k "16wmCCdPx7NOLG3" --mode cbc --iv-position suffix
```

Расшифрование с ручным `IV`:

```powershell
.\Blowfish.exe --decrypt -i "C:\Data\file.bin" -o "C:\Data\file.txt" -k "16wmCCdPx7NOLG3" --mode cbc --iv-position manual --iv-hex 0011223344556677
```

`CFB`:

```powershell
.\Blowfish.exe --encrypt -i "C:\Data\file.txt" -o "C:\Data\file.cfb" -k "16wmCCdPx7NOLG3" --mode cfb --iv-position prefix
```

## Параметры CLI

- `--encrypt`
- `--decrypt`
- `--input` / `-i`
- `--output` / `-o`
- `--key` / `-k`
- `--mode cbc|cfb`
- `--iv-position prefix|suffix|manual`
- `--iv-hex`
- `--force`
- `--help`

По умолчанию:

- `mode = cbc`
- `iv-position = prefix`

Если `--output` не задан:

- при шифровании добавляется `.bf`
- при расшифровании убирается `.bf`
- если расширения `.bf` нет, добавляется `.ubf`

## Контекстное меню

После сборки CMake публикует в папку `build`:

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

При запуске из контекстного меню открывается окно, где пользователь задаёт:

- raw key
- `mode`: `CBC` или `CFB`
- `iv-position`: `prefix`, `suffix` или `manual`
- `IV hex`, если выбран `manual`

То есть GUI не скрывает эти параметры и не подставляет старую парольную модель.

## Сборка

Обычная сборка:

```powershell
cmake -S . -B cmake-build-debug
cmake --build cmake-build-debug --target Blowfish
```

Проект собирается на встроенном локальном движке Blowfish из:

- [sources/blowfish.h](/D:/PROJECTS/BLOWFISH/sources/blowfish.h)
- [sources/blowfish.cpp](/D:/PROJECTS/BLOWFISH/sources/blowfish.cpp)

## Ограничения

- Blowfish имеет блок `64` бита, это старый алгоритм.
- Проверки целостности в формате нет.
- При неверном ключе или `IV` расшифровка может дать мусор, а в `CBC` также
  может завершиться ошибкой padding.
