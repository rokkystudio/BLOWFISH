# BlowfishTool

BlowfishTool — консольная Windows-программа для шифрования и расшифрования файлов алгоритмом Blowfish-CBC. Программа также умеет запускаться из контекстного меню Проводника и показывать Win32-окно ввода ключа.

## Модель работы

EXE остается консольным приложением. При обычном запуске из терминала он принимает аргументы командной строки. При запуске из контекстного меню Windows REG-файл передает программе специальный режим `--shell-encrypt` или `--shell-decrypt`; в этом режиме программа показывает окно ввода ключа и выполняет операцию над выбранным файлом.

Такой вариант проще и надежнее, чем один `WINDOWS`-subsystem EXE с `AttachConsole`, потому что консольный запуск из `cmd`, PowerShell и терминала работает синхронно и предсказуемо. При запуске из Проводника Windows может кратко показать консольное окно. Если нужно полностью убрать консоль при запуске из Проводника, лучше сделать второй маленький GUI-launcher EXE и оставить текущий EXE чистым CLI-инструментом.

## Криптографический формат файла

Файл содержит:

1. magic `BFW2`;
2. количество итераций PBKDF2;
3. `salt` размером 16 байт;
4. IV Blowfish-CBC размером 8 байт;
5. ciphertext;
6. HMAC-SHA256 от заголовка и ciphertext.

Пароль пользователя не используется как сырой Blowfish-ключ. Из пароля через PBKDF2-HMAC-SHA256 производится материал для Blowfish-ключа и HMAC-ключа. HMAC проверяется до расшифрования, поэтому неверный ключ и повреждение файла завершаются явной ошибкой.

## Зависимости

Проект использует OpenSSL. Для OpenSSL 3 нужен `legacy` provider, потому что Blowfish находится в legacy-наборе алгоритмов.

Один из вариантов установки через vcpkg:

```powershell
vcpkg install openssl:x64-windows
```

В CLion укажите toolchain/CMake preset, который использует vcpkg toolchain file, например:

```powershell
cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=C:\vcpkg\scripts\buildsystems\vcpkg.cmake
cmake --build build --config Release
```

Для запуска рядом с EXE должны быть runtime-файлы OpenSSL. Для OpenSSL 3 обычно нужны `libcrypto-3-x64.dll` и каталог `ossl-modules` с `legacy.dll`. Если провайдер лежит в другом месте, задайте переменную окружения `OPENSSL_MODULES` на каталог с модулями OpenSSL.

## Использование из консоли

Шифрование:

```powershell
.\BlowfishTool.exe --encrypt --input "C:\Data\file.txt" --output "C:\Data\file.txt.bfw" --ask-key
```

Расшифрование:

```powershell
.\BlowfishTool.exe --decrypt --input "C:\Data\file.txt.bfw" --output "C:\Data\file.txt" --ask-key
```

Ключ можно передать аргументом:

```powershell
.\BlowfishTool.exe --encrypt -i "C:\Data\file.txt" -o "C:\Data\file.txt.bfw" -k "my password"
```

Передача ключа через `--key` удобна для тестов, но ключ может попасть в историю команд и список процессов. Для ручной работы используйте `--ask-key`.

По умолчанию существующий выходной файл не перезаписывается. Для перезаписи используйте:

```powershell
.\BlowfishTool.exe --decrypt -i "C:\Data\file.txt.bfw" -o "C:\Data\file.txt" --ask-key --force
```

## Установка пункта в контекстное меню

REG-файл использует путь:

```text
C:\Program Files\BlowfishTool\BlowfishTool.exe
```

Перед импортом REG-файла выполните одно из двух действий:

1. положите `BlowfishTool.exe` именно в этот путь;
2. откройте `install_context_menu.reg` и замените путь на фактический путь к EXE.

Установка:

```powershell
reg import .\install_context_menu.reg
```

После установки при клике правой кнопкой по файлу появится меню:

```text
Blowfish
  Encrypt
  Decrypt
```

Режимы контекстного меню создают выходные файлы рядом с исходным файлом:

```text
Encrypt: <исходный_файл>.bfw
Decrypt: <исходный_файл>.plain
```

Удаление пункта меню:

```powershell
reg import .\uninstall_context_menu.reg
```

## Ограничения

Blowfish имеет размер блока 64 бита. Для новых форматов обычно предпочтительнее AES-GCM или ChaCha20-Poly1305, но этот проект намеренно использует Blowfish. Для снижения риска незаметной порчи данных формат содержит HMAC-SHA256.

Программа не удаляет исходный файл после шифрования и не перезаписывает выходной файл без `--force`.
