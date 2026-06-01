#include <windows.h>
#include <shellapi.h>

#include "app_resource.h"

#include <cryptopp/blowfish.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/hmac.h>
#include <cryptopp/misc.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/secblock.h>
#include <cryptopp/sha.h>

#include <algorithm>
#include <array>
#include <cstdint>
#include <cwctype>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <memory>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace
{
    using Byte = CryptoPP::byte;

    constexpr std::array<Byte, 4> FileMagic = { 'B', 'F', 'W', '2' };
    constexpr unsigned int KdfIterations = 310000;
    constexpr std::size_t SaltSize = 16;
    constexpr std::size_t IvSize = CryptoPP::Blowfish::BLOCKSIZE;
    constexpr std::size_t CipherKeySize = 32;
    constexpr std::size_t HmacKeySize = 32;
    constexpr std::size_t HmacSize = CryptoPP::SHA256::DIGESTSIZE;
    constexpr std::size_t HeaderSize = FileMagic.size() + sizeof(std::uint32_t) + SaltSize + IvSize;
    constexpr std::size_t BufferSize = 64 * 1024;
    constexpr std::array<Byte, SaltSize> FixedKdfSalt = {
        0x42, 0x6C, 0x6F, 0x77, 0x66, 0x69, 0x73, 0x68,
        0x2D, 0x46, 0x69, 0x78, 0x65, 0x64, 0x2D, 0x53
    };

    constexpr int KeyEditId = 1001;
    constexpr int FileStaticId = 1002;

    enum class Mode
    {
        None,
        Encrypt,
        Decrypt
    };

    struct Options
    {
        Mode mode = Mode::None;
        bool shellMode = false;
        bool askKey = false;
        bool force = false;
        bool help = false;
        fs::path inputPath;
        fs::path outputPath;
        std::wstring password;
    };

    struct KeyMaterial
    {
        std::array<Byte, CipherKeySize> cipherKey = {};
        std::array<Byte, HmacKeySize> hmacKey = {};
    };

    struct FileHeader
    {
        std::uint32_t iterations = 0;
        std::array<Byte, SaltSize> salt = {};
        std::array<Byte, IvSize> iv = {};
    };

    struct KeyDialogState
    {
        std::wstring title;
        std::wstring filePath;
        std::wstring password;
        HWND editHandle = nullptr;
        bool accepted = false;
    };

    class UsageError : public std::runtime_error
    {
    public:
        using std::runtime_error::runtime_error;
    };

    /**
     * Переводит UTF-16 строку Windows в UTF-8.
     */
    std::string toUtf8(std::wstring_view value)
    {
        if (value.empty())
        {
            return {};
        }

        if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        {
            throw std::runtime_error("UTF-16 string is too large");
        }

        const int wideSize = static_cast<int>(value.size());
        const int requiredSize = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), wideSize, nullptr, 0, nullptr, nullptr);
        if (requiredSize <= 0)
        {
            throw std::runtime_error("WideCharToMultiByte failed");
        }

        std::string result(static_cast<std::size_t>(requiredSize), '\0');
        const int writtenSize = WideCharToMultiByte(CP_UTF8, WC_ERR_INVALID_CHARS, value.data(), wideSize, result.data(), requiredSize, nullptr, nullptr);
        if (writtenSize != requiredSize)
        {
            throw std::runtime_error("WideCharToMultiByte wrote unexpected byte count");
        }

        return result;
    }

    /**
     * Переводит UTF-8 строку в UTF-16 строку Windows.
     */
    std::wstring fromUtf8(std::string_view value)
    {
        if (value.empty())
        {
            return {};
        }

        if (value.size() > static_cast<std::size_t>(std::numeric_limits<int>::max()))
        {
            throw std::runtime_error("UTF-8 string is too large");
        }

        const int byteSize = static_cast<int>(value.size());
        const int requiredSize = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), byteSize, nullptr, 0);
        if (requiredSize <= 0)
        {
            throw std::runtime_error("MultiByteToWideChar failed");
        }

        std::wstring result(static_cast<std::size_t>(requiredSize), L'\0');
        const int writtenSize = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, value.data(), byteSize, result.data(), requiredSize);
        if (writtenSize != requiredSize)
        {
            throw std::runtime_error("MultiByteToWideChar wrote unexpected code unit count");
        }

        return result;
    }

    /**
     * Возвращает путь в кавычках для диагностических сообщений.
     */
    std::string quotePath(const fs::path& path)
    {
        return "\"" + toUtf8(path.wstring()) + "\"";
    }

    /**
     * Настраивает кодировку консоли Windows на UTF-8.
     */
    void configureConsole()
    {
        SetConsoleCP(CP_UTF8);
        SetConsoleOutputCP(CP_UTF8);
    }

    /**
     * Добавляет 32-битное число в буфер в little-endian формате.
     */
    void appendUint32Le(std::vector<Byte>& buffer, std::uint32_t value)
    {
        buffer.push_back(static_cast<Byte>(value & 0xFFu));
        buffer.push_back(static_cast<Byte>((value >> 8u) & 0xFFu));
        buffer.push_back(static_cast<Byte>((value >> 16u) & 0xFFu));
        buffer.push_back(static_cast<Byte>((value >> 24u) & 0xFFu));
    }

    /**
     * Читает 32-битное число из массива в little-endian формате.
     */
    std::uint32_t readUint32Le(const std::array<Byte, sizeof(std::uint32_t)>& buffer)
    {
        return static_cast<std::uint32_t>(buffer[0])
            | (static_cast<std::uint32_t>(buffer[1]) << 8u)
            | (static_cast<std::uint32_t>(buffer[2]) << 16u)
            | (static_cast<std::uint32_t>(buffer[3]) << 24u);
    }

    /**
     * Заполняет массив криптографически стойкими случайными байтами.
     */
    template <std::size_t Size>
    std::array<Byte, Size> randomBytes()
    {
        std::array<Byte, Size> result = {};

        CryptoPP::AutoSeededRandomPool randomPool;
        randomPool.GenerateBlock(result.data(), result.size());

        return result;
    }

    /**
     * Возвращает заголовок файла Blowfish.
     */
    std::vector<Byte> buildHeader(
        std::uint32_t iterations,
        const std::array<Byte, SaltSize>& salt,
        const std::array<Byte, IvSize>& iv)
    {
        std::vector<Byte> header;
        header.reserve(HeaderSize);

        header.insert(header.end(), FileMagic.begin(), FileMagic.end());
        appendUint32Le(header, iterations);
        header.insert(header.end(), salt.begin(), salt.end());
        header.insert(header.end(), iv.begin(), iv.end());

        return header;
    }

    /**
     * Читает точное количество байтов из входного файла.
     */
    void readExact(std::ifstream& input, Byte* output, std::size_t size, std::string_view description)
    {
        input.read(reinterpret_cast<char*>(output), static_cast<std::streamsize>(size));

        if (input.gcount() != static_cast<std::streamsize>(size))
        {
            std::ostringstream message;
            message << "Cannot read " << description;
            throw std::runtime_error(message.str());
        }
    }

    /**
     * Читает и проверяет заголовок файла Blowfish.
     */
    FileHeader readHeader(std::ifstream& input)
    {
        std::array<Byte, FileMagic.size()> magic = {};
        readExact(input, magic.data(), magic.size(), "file magic");

        if (magic != FileMagic)
        {
            throw std::runtime_error("Input file has unsupported format");
        }

        std::array<Byte, sizeof(std::uint32_t)> iterationBytes = {};
        readExact(input, iterationBytes.data(), iterationBytes.size(), "KDF iteration count");

        FileHeader header;
        header.iterations = readUint32Le(iterationBytes);

        if (header.iterations == 0)
        {
            throw std::runtime_error("Input file has invalid KDF iteration count");
        }

        readExact(input, header.salt.data(), header.salt.size(), "salt");
        readExact(input, header.iv.data(), header.iv.size(), "initialization vector");

        return header;
    }

    /**
     * Читает заголовок файла Blowfish из указанного пути.
     */
    FileHeader readHeaderFromFile(const fs::path& inputPath)
    {
        std::ifstream input(inputPath, std::ios::binary);
        if (!input)
        {
            throw std::runtime_error("Cannot open input file " + quotePath(inputPath));
        }

        return readHeader(input);
    }

    /**
     * Производит ключи шифрования и HMAC из пользовательского пароля.
     */
    KeyMaterial deriveKeyMaterial(
        const std::wstring& password,
        const std::array<Byte, SaltSize>& salt,
        std::uint32_t iterations)
    {
        if (password.empty())
        {
            throw std::runtime_error("Key cannot be empty");
        }

        std::string passwordUtf8 = toUtf8(password);
        std::array<Byte, CipherKeySize + HmacKeySize> rawKey = {};

        CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
        pbkdf.DeriveKey(
            rawKey.data(),
            rawKey.size(),
            0,
            reinterpret_cast<const Byte*>(passwordUtf8.data()),
            passwordUtf8.size(),
            salt.data(),
            salt.size(),
            iterations);

        KeyMaterial material;
        std::copy_n(rawKey.begin(), material.cipherKey.size(), material.cipherKey.begin());
        std::copy_n(rawKey.begin() + material.cipherKey.size(), material.hmacKey.size(), material.hmacKey.begin());

        SecureZeroMemory(rawKey.data(), rawKey.size());
        SecureZeroMemory(passwordUtf8.data(), passwordUtf8.size());

        return material;
    }

    /**
     * Очищает ключевой материал из памяти.
     */
    void clearKeyMaterial(KeyMaterial& material)
    {
        SecureZeroMemory(material.cipherKey.data(), material.cipherKey.size());
        SecureZeroMemory(material.hmacKey.data(), material.hmacKey.size());
    }

    /**
     * Производит IV из уже полученного ключевого материала.
     */
    std::array<Byte, IvSize> deriveIvFromKeyMaterial(const KeyMaterial& material)
    {
        std::array<Byte, IvSize> iv = {};
        std::copy_n(material.hmacKey.begin(), iv.size(), iv.begin());
        return iv;
    }

    /**
     * Вычисляет HMAC-SHA256 для потока байтов.
     */
    class HmacSha256
    {
    public:
        explicit HmacSha256(const std::array<Byte, HmacKeySize>& key)
            : hmac_(key.data(), key.size())
        {
        }

        /**
         * Добавляет байты в текущий HMAC.
         */
        void update(const Byte* data, std::size_t size)
        {
            if (size == 0)
            {
                return;
            }

            hmac_.Update(data, size);
        }

        /**
         * Возвращает итоговый HMAC-SHA256.
         */
        std::array<Byte, HmacSize> final()
        {
            std::array<Byte, HmacSize> result = {};
            hmac_.Final(result.data());
            return result;
        }

    private:
        CryptoPP::HMAC<CryptoPP::SHA256> hmac_;
    };

    /**
     * Проверяет входной и выходной пути для операции с файлом.
     */
    void validateFilePaths(const fs::path& inputPath, const fs::path& outputPath, bool force)
    {
        std::error_code error;

        if (!fs::exists(inputPath, error))
        {
            throw std::runtime_error("Input file does not exist " + quotePath(inputPath));
        }

        if (fs::is_directory(inputPath, error))
        {
            throw std::runtime_error("Input path is a directory " + quotePath(inputPath));
        }

        const fs::path absoluteInput = fs::absolute(inputPath, error);
        if (error)
        {
            throw std::runtime_error("Cannot resolve input path " + quotePath(inputPath));
        }

        const fs::path absoluteOutput = fs::absolute(outputPath, error);
        if (error)
        {
            throw std::runtime_error("Cannot resolve output path " + quotePath(outputPath));
        }

        if (absoluteInput.lexically_normal() == absoluteOutput.lexically_normal())
        {
            throw std::runtime_error("Input and output paths must be different");
        }

        if (!force && fs::exists(outputPath, error))
        {
            throw std::runtime_error("Output file already exists " + quotePath(outputPath));
        }
    }

    /**
     * Возвращает временный путь для атомарной записи выходного файла.
     */
    fs::path prepareTemporaryOutputPath(const fs::path& outputPath, bool force)
    {
        fs::path temporaryPath = outputPath;
        temporaryPath += L".tmp";

        std::error_code error;
        if (fs::exists(temporaryPath, error))
        {
            if (!force)
            {
                throw std::runtime_error("Temporary output file already exists " + quotePath(temporaryPath));
            }

            fs::remove(temporaryPath, error);
            if (error)
            {
                throw std::runtime_error("Cannot remove temporary output file " + quotePath(temporaryPath));
            }
        }

        return temporaryPath;
    }

    /**
     * Перемещает временный файл в итоговый выходной путь.
     */
    void finalizeTemporaryOutput(const fs::path& temporaryPath, const fs::path& outputPath, bool force)
    {
        std::error_code error;

        if (force && fs::exists(outputPath, error))
        {
            fs::remove(outputPath, error);
            if (error)
            {
                throw std::runtime_error("Cannot remove existing output file " + quotePath(outputPath));
            }
        }

        fs::rename(temporaryPath, outputPath, error);
        if (error)
        {
            throw std::runtime_error("Cannot move temporary output file to " + quotePath(outputPath));
        }
    }

    /**
     * Удаляет временный файл, оставшийся после неуспешной операции.
     */
    void removeTemporaryOutput(const fs::path& temporaryPath)
    {
        std::error_code ignored;
        fs::remove(temporaryPath, ignored);
    }

    /**
     * Записывает байты в выходной поток и проверяет состояние потока.
     */
    void writeBytes(std::ofstream& output, const Byte* data, std::size_t size)
    {
        if (size == 0)
        {
            return;
        }

        output.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
        if (!output)
        {
            throw std::runtime_error("Cannot write output file");
        }
    }

    /**
     * Записывает накопленные байты Crypto++ фильтра в выходной файл.
     */
    void drainFilter(
        CryptoPP::StreamTransformationFilter& filter,
        std::ofstream& output,
        HmacSha256* hmac)
    {
        std::array<Byte, BufferSize + CryptoPP::Blowfish::BLOCKSIZE> outputBuffer = {};

        while (filter.MaxRetrievable() > 0)
        {
            const std::size_t chunkSize = static_cast<std::size_t>(
                std::min<CryptoPP::lword>(filter.MaxRetrievable(), outputBuffer.size()));

            const std::size_t readSize = filter.Get(outputBuffer.data(), chunkSize);

            if (readSize > 0)
            {
                if (hmac != nullptr)
                {
                    hmac->update(outputBuffer.data(), readSize);
                }

                writeBytes(output, outputBuffer.data(), readSize);
            }
        }
    }

    /**
     * Вычисляет HMAC-SHA256 для префикса файла заданной длины.
     */
    std::array<Byte, HmacSize> computeFilePrefixHmac(
        const fs::path& inputPath,
        std::uintmax_t prefixSize,
        const std::array<Byte, HmacKeySize>& hmacKey)
    {
        std::ifstream input(inputPath, std::ios::binary);
        if (!input)
        {
            throw std::runtime_error("Cannot open input file " + quotePath(inputPath));
        }

        HmacSha256 hmac(hmacKey);
        std::array<Byte, BufferSize> buffer = {};
        std::uintmax_t remainingSize = prefixSize;

        while (remainingSize > 0)
        {
            const std::size_t chunkSize = static_cast<std::size_t>(std::min<std::uintmax_t>(remainingSize, buffer.size()));
            input.read(reinterpret_cast<char*>(buffer.data()), static_cast<std::streamsize>(chunkSize));

            if (input.gcount() != static_cast<std::streamsize>(chunkSize))
            {
                throw std::runtime_error("Cannot read bytes for HMAC validation");
            }

            hmac.update(buffer.data(), chunkSize);
            remainingSize -= chunkSize;
        }

        return hmac.final();
    }

    /**
     * Читает HMAC-SHA256 из хвоста файла.
     */
    std::array<Byte, HmacSize> readStoredHmac(const fs::path& inputPath, std::uintmax_t hmacOffset)
    {
        std::ifstream input(inputPath, std::ios::binary);
        if (!input)
        {
            throw std::runtime_error("Cannot open input file " + quotePath(inputPath));
        }

        input.seekg(static_cast<std::streamoff>(hmacOffset), std::ios::beg);
        if (!input)
        {
            throw std::runtime_error("Cannot seek to HMAC in input file");
        }

        std::array<Byte, HmacSize> hmac = {};
        readExact(input, hmac.data(), hmac.size(), "HMAC");

        return hmac;
    }

    /**
     * Возвращает true, когда два HMAC равны при сравнении с постоянным временем.
     */
    bool hmacEquals(
        const std::array<Byte, HmacSize>& left,
        const std::array<Byte, HmacSize>& right)
    {
        return CryptoPP::VerifyBufsEqual(left.data(), right.data(), left.size());
    }

    /**
     * Шифрует файл Blowfish-CBC и добавляет заголовок, salt, IV и HMAC-SHA256.
     */
    void encryptFile(
        const fs::path& inputPath,
        const fs::path& outputPath,
        const std::wstring& password,
        bool force)
    {
        validateFilePaths(inputPath, outputPath, force);

        const fs::path temporaryPath = prepareTemporaryOutputPath(outputPath, force);

        KeyMaterial keyMaterial = deriveKeyMaterial(password, FixedKdfSalt, KdfIterations);
        const auto iv = deriveIvFromKeyMaterial(keyMaterial);

        try
        {
            std::ifstream input(inputPath, std::ios::binary);
            if (!input)
            {
                throw std::runtime_error("Cannot open input file " + quotePath(inputPath));
            }

            std::ofstream output(temporaryPath, std::ios::binary);
            if (!output)
            {
                throw std::runtime_error("Cannot create output file " + quotePath(temporaryPath));
            }

            CryptoPP::CFB_Mode<CryptoPP::Blowfish>::Encryption encryption;
            encryption.SetKeyWithIV(keyMaterial.cipherKey.data(), keyMaterial.cipherKey.size(), iv.data(), iv.size());

            CryptoPP::StreamTransformationFilter filter(
                encryption,
                nullptr,
                CryptoPP::StreamTransformationFilter::NO_PADDING);

            std::array<Byte, BufferSize> inputBuffer = {};

            for (;;)
            {
                input.read(reinterpret_cast<char*>(inputBuffer.data()), static_cast<std::streamsize>(inputBuffer.size()));
                const std::streamsize readSize = input.gcount();

                if (readSize > 0)
                {
                    filter.Put(inputBuffer.data(), static_cast<std::size_t>(readSize));
                    drainFilter(filter, output, nullptr);
                }

                if (input.eof())
                {
                    break;
                }

                if (!input)
                {
                    throw std::runtime_error("Cannot read input file " + quotePath(inputPath));
                }
            }

            filter.MessageEnd();
            drainFilter(filter, output, nullptr);

            output.close();
            if (!output)
            {
                throw std::runtime_error("Cannot finalize output file " + quotePath(temporaryPath));
            }

            finalizeTemporaryOutput(temporaryPath, outputPath, force);
            clearKeyMaterial(keyMaterial);
        }
        catch (...)
        {
            clearKeyMaterial(keyMaterial);
            removeTemporaryOutput(temporaryPath);
            throw;
        }
    }

    /**
     * Расшифровывает файл Blowfish после проверки HMAC-SHA256.
     */
    void decryptFile(
        const fs::path& inputPath,
        const fs::path& outputPath,
        const std::wstring& password,
        bool force)
    {
        validateFilePaths(inputPath, outputPath, force);
        KeyMaterial keyMaterial = deriveKeyMaterial(password, FixedKdfSalt, KdfIterations);
        const auto iv = deriveIvFromKeyMaterial(keyMaterial);
        const fs::path temporaryPath = prepareTemporaryOutputPath(outputPath, force);

        try
        {
            std::ifstream input(inputPath, std::ios::binary);
            if (!input)
            {
                throw std::runtime_error("Cannot open input file " + quotePath(inputPath));
            }

            std::ofstream output(temporaryPath, std::ios::binary);
            if (!output)
            {
                throw std::runtime_error("Cannot create output file " + quotePath(temporaryPath));
            }

            CryptoPP::CFB_Mode<CryptoPP::Blowfish>::Decryption decryption;
            decryption.SetKeyWithIV(keyMaterial.cipherKey.data(), keyMaterial.cipherKey.size(), iv.data(), iv.size());

            CryptoPP::StreamTransformationFilter filter(
                decryption,
                nullptr,
                CryptoPP::StreamTransformationFilter::NO_PADDING);

            std::array<Byte, BufferSize> inputBuffer = {};

            for (;;)
            {
                input.read(reinterpret_cast<char*>(inputBuffer.data()), static_cast<std::streamsize>(inputBuffer.size()));
                const std::streamsize readSize = input.gcount();

                if (readSize > 0)
                {
                    filter.Put(inputBuffer.data(), static_cast<std::size_t>(readSize));
                    drainFilter(filter, output, nullptr);
                }

                if (input.eof())
                {
                    break;
                }

                if (!input)
                {
                    throw std::runtime_error("Cannot read input file " + quotePath(inputPath));
                }
            }

            filter.MessageEnd();
            drainFilter(filter, output, nullptr);

            output.close();
            if (!output)
            {
                throw std::runtime_error("Cannot finalize output file " + quotePath(temporaryPath));
            }

            finalizeTemporaryOutput(temporaryPath, outputPath, force);
            clearKeyMaterial(keyMaterial);
        }
        catch (...)
        {
            clearKeyMaterial(keyMaterial);
            removeTemporaryOutput(temporaryPath);
            throw;
        }
    }

    /**
     * Устанавливает режим операции и запрещает указание нескольких режимов одновременно.
     */
    void setMode(Options& options, Mode mode)
    {
        if (options.mode != Mode::None && options.mode != mode)
        {
            throw UsageError("Only one mode can be specified");
        }

        options.mode = mode;
    }

    /**
     * Возвращает следующий аргумент командной строки.
     */
    std::wstring nextArgument(int& index, int argc, wchar_t** argv, std::wstring_view optionName)
    {
        if (index + 1 >= argc)
        {
            throw UsageError("Missing value for " + toUtf8(optionName));
        }

        ++index;
        return argv[index];
    }

    /**
     * Разбирает аргументы командной строки.
     */
    Options parseOptions(int argc, wchar_t** argv)
    {
        Options options;

        for (int index = 1; index < argc; ++index)
        {
            const std::wstring_view argument = argv[index];

            if (argument == L"--help" || argument == L"-h")
            {
                options.help = true;
            }
            else if (argument == L"--encrypt")
            {
                setMode(options, Mode::Encrypt);
            }
            else if (argument == L"--decrypt")
            {
                setMode(options, Mode::Decrypt);
            }
            else if (argument == L"--shell-encrypt")
            {
                options.shellMode = true;
                setMode(options, Mode::Encrypt);
                options.inputPath = nextArgument(index, argc, argv, argument);
            }
            else if (argument == L"--shell-decrypt")
            {
                options.shellMode = true;
                setMode(options, Mode::Decrypt);
                options.inputPath = nextArgument(index, argc, argv, argument);
            }
            else if (argument == L"--input" || argument == L"-i")
            {
                options.inputPath = nextArgument(index, argc, argv, argument);
            }
            else if (argument == L"--output" || argument == L"-o")
            {
                options.outputPath = nextArgument(index, argc, argv, argument);
            }
            else if (argument == L"--key" || argument == L"-k")
            {
                options.password = nextArgument(index, argc, argv, argument);
            }
            else if (argument == L"--ask-key")
            {
                options.askKey = true;
            }
            else if (argument == L"--force")
            {
                options.force = true;
            }
            else
            {
                throw UsageError("Unknown argument " + toUtf8(argument));
            }
        }

        return options;
    }

    /**
     * Печатает справку CLI.
     */
    void printHelp()
    {
        std::wcout
            << L"Blowfish\n\n"
            << L"Шифрование:\n"
            << L"  Blowfish.exe --encrypt --input <file> --ask-key\n"
            << L"  Blowfish.exe --encrypt -i <file> -o <output> -k <key>\n\n"
            << L"Расшифрование:\n"
            << L"  Blowfish.exe --decrypt --input <file> --ask-key\n"
            << L"  Blowfish.exe --decrypt -i <file> -o <output> -k <key>\n\n"
            << L"Выходной файл по умолчанию (если не указан --output):\n"
            << L"  encrypt + .zip  -> .pack\n"
            << L"  decrypt + .pack -> .zip\n"
            << L"  encrypt         -> <input>.bf\n"
            << L"  decrypt + .bf   -> убрать .bf\n"
            << L"  decrypt         -> <input>.ubf\n\n"
            << L"Параметры:\n"
            << L"  --output    путь выходного файла (необязательно)\n"
            << L"  --force     перезаписывает существующий выходной файл\n"
            << L"  --ask-key   запрашивает ключ в консоли без вывода символов\n"
            << L"  --key       принимает ключ из аргумента командной строки\n"
            << L"  --help      показывает эту справку\n";
    }

    /**
     * Читает ключ из консоли без отображения введенных символов.
     */
    std::wstring readPasswordFromConsole()
    {
        std::wcout << L"Ключ: ";

        HANDLE inputHandle = GetStdHandle(STD_INPUT_HANDLE);
        DWORD originalMode = 0;
        const bool canHideInput = inputHandle != INVALID_HANDLE_VALUE && GetConsoleMode(inputHandle, &originalMode);

        if (canHideInput)
        {
            SetConsoleMode(inputHandle, originalMode & ~ENABLE_ECHO_INPUT);
        }

        std::wstring password;
        std::getline(std::wcin, password);

        if (canHideInput)
        {
            SetConsoleMode(inputHandle, originalMode);
        }

        std::wcout << L"\n";

        return password;
    }

    /**
     * Назначает стандартный GUI-шрифт указанному контролу.
     */
    void setDefaultGuiFont(HWND handle)
    {
        SendMessageW(handle, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
    }

    /**
     * Создает дочерний элемент окна и назначает ему стандартный GUI-шрифт.
     */
    HWND createChildWindow(
        HWND parent,
        const wchar_t* className,
        const std::wstring& text,
        DWORD style,
        int x,
        int y,
        int width,
        int height,
        int controlId)
    {
        HWND handle = CreateWindowExW(
            0,
            className,
            text.c_str(),
            WS_CHILD | WS_VISIBLE | style,
            x,
            y,
            width,
            height,
            parent,
            reinterpret_cast<HMENU>(static_cast<INT_PTR>(controlId)),
            GetModuleHandleW(nullptr),
            nullptr);

        if (handle == nullptr)
        {
            throw std::runtime_error("Cannot create dialog control");
        }

        setDefaultGuiFont(handle);
        return handle;
    }

    /**
     * Обрабатывает сообщения окна ввода ключа.
     */
    LRESULT CALLBACK keyDialogProc(HWND windowHandle, UINT message, WPARAM wParam, LPARAM lParam)
    {
        KeyDialogState* state = reinterpret_cast<KeyDialogState*>(GetWindowLongPtrW(windowHandle, GWLP_USERDATA));

        switch (message)
        {
            case WM_CREATE:
            {
                const auto* createStruct = reinterpret_cast<CREATESTRUCTW*>(lParam);
                state = reinterpret_cast<KeyDialogState*>(createStruct->lpCreateParams);
                SetWindowLongPtrW(windowHandle, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(state));

                createChildWindow(windowHandle, L"STATIC", L"Файл:", 0, 16, 16, 448, 18, FileStaticId);
                createChildWindow(windowHandle, L"STATIC", state->filePath, SS_LEFTNOWORDWRAP, 16, 36, 448, 18, FileStaticId + 1);
                createChildWindow(windowHandle, L"STATIC", L"Ключ:", 0, 16, 68, 448, 18, FileStaticId + 2);

                state->editHandle = createChildWindow(
                    windowHandle,
                    L"EDIT",
                    L"",
                    WS_BORDER | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
                    16,
                    88,
                    448,
                    24,
                    KeyEditId);

                SendMessageW(state->editHandle, EM_SETPASSWORDCHAR, L'*', 0);

                createChildWindow(windowHandle, L"BUTTON", L"OK", WS_TABSTOP | BS_DEFPUSHBUTTON, 272, 126, 90, 28, IDOK);
                createChildWindow(windowHandle, L"BUTTON", L"Cancel", WS_TABSTOP | BS_PUSHBUTTON, 374, 126, 90, 28, IDCANCEL);

                SetFocus(state->editHandle);
                return 0;
            }

            case WM_COMMAND:
            {
                const int commandId = LOWORD(wParam);

                if (commandId == IDOK)
                {
                    if (state == nullptr || state->editHandle == nullptr)
                    {
                        DestroyWindow(windowHandle);
                        return 0;
                    }

                    const int length = GetWindowTextLengthW(state->editHandle);
                    std::wstring password(static_cast<std::size_t>(length) + 1, L'\0');
                    GetWindowTextW(state->editHandle, password.data(), length + 1);
                    password.resize(static_cast<std::size_t>(length));

                    if (password.empty())
                    {
                        MessageBoxW(windowHandle, L"Ключ не может быть пустым.", state->title.c_str(), MB_OK | MB_ICONERROR);
                        return 0;
                    }

                    state->password = std::move(password);
                    state->accepted = true;
                    DestroyWindow(windowHandle);
                    return 0;
                }

                if (commandId == IDCANCEL)
                {
                    DestroyWindow(windowHandle);
                    return 0;
                }

                break;
            }

            case WM_CLOSE:
                DestroyWindow(windowHandle);
                return 0;

            case WM_DESTROY:
                PostQuitMessage(0);
                return 0;

            default:
                break;
        }

        return DefWindowProcW(windowHandle, message, wParam, lParam);
    }

    /**
     * Регистрирует класс окна ввода ключа.
     */
    void registerKeyDialogClass()
    {
        const wchar_t* className = L"BlowfishKeyDialog";
        HINSTANCE instanceHandle = GetModuleHandleW(nullptr);
        HICON appIcon = LoadIconW(instanceHandle, MAKEINTRESOURCEW(IDI_APP_ICON));

        WNDCLASSEXW windowClass = {};
        windowClass.cbSize = sizeof(windowClass);
        windowClass.lpfnWndProc = keyDialogProc;
        windowClass.hInstance = instanceHandle;
        windowClass.hCursor = LoadCursorW(nullptr, MAKEINTRESOURCEW(32512));
        windowClass.hbrBackground = reinterpret_cast<HBRUSH>(COLOR_WINDOW + 1);
        windowClass.lpszClassName = className;
        windowClass.hIcon = appIcon;
        windowClass.hIconSm = appIcon;

        if (RegisterClassExW(&windowClass) == 0)
        {
            const DWORD error = GetLastError();
            if (error != ERROR_CLASS_ALREADY_EXISTS)
            {
                throw std::runtime_error("Cannot register key dialog window class");
            }
        }
    }

    /**
     * Показывает модальное окно ввода ключа.
     */
    bool promptPasswordWithDialog(const std::wstring& title, const fs::path& inputPath, std::wstring& password)
    {
        registerKeyDialogClass();

        RECT workArea = {};
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);

        constexpr int width = 500;
        constexpr int height = 204;
        const int x = workArea.left + ((workArea.right - workArea.left) - width) / 2;
        const int y = workArea.top + ((workArea.bottom - workArea.top) - height) / 2;

        KeyDialogState state;
        state.title = title;
        state.filePath = inputPath.wstring();

        HWND windowHandle = CreateWindowExW(
            WS_EX_DLGMODALFRAME | WS_EX_TOPMOST,
            L"BlowfishKeyDialog",
            title.c_str(),
            WS_CAPTION | WS_SYSMENU,
            x,
            y,
            width,
            height,
            nullptr,
            nullptr,
            GetModuleHandleW(nullptr),
            &state);

        if (windowHandle == nullptr)
        {
            throw std::runtime_error("Cannot create key dialog");
        }

        HICON appIcon = LoadIconW(GetModuleHandleW(nullptr), MAKEINTRESOURCEW(IDI_APP_ICON));
        if (appIcon != nullptr)
        {
            SendMessageW(windowHandle, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(appIcon));
            SendMessageW(windowHandle, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(appIcon));
        }

        setDefaultGuiFont(windowHandle);
        ShowWindow(windowHandle, SW_SHOW);
        UpdateWindow(windowHandle);

        MSG message = {};
        while (GetMessageW(&message, nullptr, 0, 0) > 0)
        {
            if (!IsDialogMessageW(windowHandle, &message))
            {
                TranslateMessage(&message);
                DispatchMessageW(&message);
            }

            if (!IsWindow(windowHandle))
            {
                break;
            }
        }

        if (state.accepted)
        {
            password = std::move(state.password);
            return true;
        }

        return false;
    }

    std::wstring toLower(std::wstring value)
    {
        std::transform(
            value.begin(),
            value.end(),
            value.begin(),
            [](const wchar_t symbol)
            {
                return static_cast<wchar_t>(std::towlower(symbol));
            });

        return value;
    }

    bool extensionEquals(const fs::path& path, std::wstring_view extension)
    {
        return toLower(path.extension().wstring()) == toLower(std::wstring(extension));
    }

    /**
     * Возвращает выходной путь по умолчанию, если --output не указан.
     */
    fs::path makeAutomaticOutputPath(const fs::path& inputPath, Mode mode)
    {
        auto replaceExtension = [&](std::wstring_view extension)
        {
            fs::path outputPath = inputPath;
            outputPath.replace_extension(extension);
            return outputPath;
        };

        if (mode == Mode::Encrypt)
        {
            if (extensionEquals(inputPath, L".zip"))
            {
                return replaceExtension(L".pack");
            }

            fs::path outputPath = inputPath;
            outputPath += L".bf";
            return outputPath;
        }

        if (extensionEquals(inputPath, L".pack"))
        {
            return replaceExtension(L".zip");
        }

        if (extensionEquals(inputPath, L".bf"))
        {
            return replaceExtension(L"");
        }

        fs::path outputPath = inputPath;
        outputPath += L".ubf";
        return outputPath;
    }

    /**
     * Показывает сообщение об ошибке.
     */
    void showErrorMessage(const std::wstring& message)
    {
        MessageBoxW(nullptr, message.c_str(), L"Blowfish", MB_OK | MB_ICONERROR);
    }

    /**
     * Показывает сообщение об успешном завершении операции.
     */
    void showSuccessMessage(const fs::path& inputPath, const fs::path& outputPath)
    {
        std::wstring message = L"Операция завершена.\n\nВход:\n";
        message += inputPath.wstring();
        message += L"\n\nВыход:\n";
        message += outputPath.wstring();

        MessageBoxW(nullptr, message.c_str(), L"Blowfish", MB_OK | MB_ICONINFORMATION);
    }

    /**
     * Выполняет операцию, запущенную из контекстного меню Windows.
     */
    int executeShellMode(const Options& options)
    {
        const fs::path outputPath = makeAutomaticOutputPath(options.inputPath, options.mode);

        std::wstring password;
        const std::wstring title = options.mode == Mode::Encrypt
            ? L"Blowfish Encrypt"
            : L"Blowfish Decrypt";

        if (!promptPasswordWithDialog(title, options.inputPath, password))
        {
            return 2;
        }

        if (options.mode == Mode::Encrypt)
        {
            encryptFile(options.inputPath, outputPath, password, false);
        }
        else
        {
            decryptFile(options.inputPath, outputPath, password, false);
        }

        SecureZeroMemory(password.data(), password.size() * sizeof(wchar_t));
        showSuccessMessage(options.inputPath, outputPath);

        return 0;
    }

    /**
     * Выполняет операцию, запущенную из консоли.
     */
    int executeConsoleMode(Options& options)
    {
        if (options.outputPath.empty())
        {
            options.outputPath = makeAutomaticOutputPath(options.inputPath, options.mode);
        }

        if (options.password.empty() && options.askKey)
        {
            options.password = readPasswordFromConsole();
        }

        if (options.password.empty())
        {
            throw UsageError("Key is required. Use --ask-key or --key <value>");
        }

        if (options.mode == Mode::Encrypt)
        {
            encryptFile(options.inputPath, options.outputPath, options.password, options.force);
        }
        else
        {
            decryptFile(options.inputPath, options.outputPath, options.password, options.force);
        }

        SecureZeroMemory(options.password.data(), options.password.size() * sizeof(wchar_t));

        std::wcout << L"Готово: " << options.outputPath.wstring() << L"\n";
        return 0;
    }

    /**
     * Проверяет обязательные параметры и запускает выбранный режим.
     */
    int execute(Options& options)
    {
        if (options.help)
        {
            printHelp();
            return 0;
        }

        if (options.mode == Mode::None)
        {
            throw UsageError("Mode is required: --encrypt or --decrypt");
        }

        if (options.inputPath.empty())
        {
            throw UsageError("Input path is required");
        }

        if (options.shellMode)
        {
            return executeShellMode(options);
        }

        return executeConsoleMode(options);
    }
}

/**
 * Точка входа приложения Blowfish.
 */
int wmain(int argc, wchar_t** argv)
{
    configureConsole();

    Options options;

    try
    {
        options = parseOptions(argc, argv);
        return execute(options);
    }
    catch (const UsageError& exception)
    {
        if (options.shellMode)
        {
            showErrorMessage(fromUtf8(exception.what()));
        }
        else
        {
            std::cerr << "Ошибка: " << exception.what() << "\n\n";
            printHelp();
        }

        return 1;
    }
    catch (const std::exception& exception)
    {
        if (options.shellMode)
        {
            showErrorMessage(fromUtf8(exception.what()));
        }
        else
        {
            std::cerr << "Ошибка: " << exception.what() << "\n";
        }

        return 1;
    }
}
