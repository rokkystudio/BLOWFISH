#include <windows.h>
#include <shellapi.h>
#include <bcrypt.h>

#include "app_resource.h"
#include "blowfish.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cwctype>
#include <exception>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <limits>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace
{
    using Byte = blowfish::Byte;

    constexpr std::size_t IvSize = blowfish::Blowfish::BlockSize;

    constexpr int FileStaticId = 1001;
    constexpr int KeyEditId = 1002;
    constexpr int ModeCbcId = 1003;
    constexpr int ModeCfbId = 1004;
    constexpr int IvPrefixId = 1005;
    constexpr int IvSuffixId = 1006;
    constexpr int IvManualId = 1007;
    constexpr int IvEditId = 1008;

    enum class OperationMode
    {
        None,
        Encrypt,
        Decrypt
    };

    enum class CipherMode
    {
        Cbc,
        Cfb
    };

    enum class IvMode
    {
        Prefix,
        Suffix,
        Manual
    };

    struct Options
    {
        OperationMode operation = OperationMode::None;
        CipherMode cipherMode = CipherMode::Cbc;
        IvMode ivMode = IvMode::Prefix;
        bool shellMode = false;
        bool force = false;
        bool help = false;
        fs::path inputPath;
        fs::path outputPath;
        std::wstring keyText;
        std::wstring ivHex;
    };

    struct KeyDialogState
    {
        std::wstring title;
        std::wstring filePath;
        std::wstring keyText;
        std::wstring ivHex;
        CipherMode cipherMode = CipherMode::Cbc;
        IvMode ivMode = IvMode::Prefix;
        HWND keyEditHandle = nullptr;
        HWND ivEditHandle = nullptr;
        bool accepted = false;
    };

    class UsageError : public std::runtime_error
    {
    public:
        using std::runtime_error::runtime_error;
    };

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

    std::string quotePath(const fs::path& path)
    {
        return "\"" + toUtf8(path.wstring()) + "\"";
    }

    void configureConsole()
    {
        SetConsoleCP(CP_UTF8);
        SetConsoleOutputCP(CP_UTF8);
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

    template <std::size_t Size>
    std::array<Byte, Size> randomBytes()
    {
        std::array<Byte, Size> result = {};
        const NTSTATUS status = BCryptGenRandom(
            nullptr,
            reinterpret_cast<PUCHAR>(result.data()),
            static_cast<ULONG>(result.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        if (status < 0)
        {
            throw std::runtime_error("Cannot generate random bytes for IV");
        }

        return result;
    }

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

    void removeTemporaryOutput(const fs::path& temporaryPath)
    {
        std::error_code ignored;
        fs::remove(temporaryPath, ignored);
    }

    std::vector<Byte> readAllBytes(const fs::path& inputPath)
    {
        std::ifstream input(inputPath, std::ios::binary);
        if (!input)
        {
            throw std::runtime_error("Cannot open input file " + quotePath(inputPath));
        }

        input.seekg(0, std::ios::end);
        const std::streamoff endPosition = input.tellg();
        if (endPosition < 0)
        {
            throw std::runtime_error("Cannot determine input file size " + quotePath(inputPath));
        }

        input.seekg(0, std::ios::beg);
        std::vector<Byte> bytes(static_cast<std::size_t>(endPosition), 0);

        if (!bytes.empty())
        {
            input.read(reinterpret_cast<char*>(bytes.data()), endPosition);
            if (input.gcount() != endPosition)
            {
                throw std::runtime_error("Cannot read input file " + quotePath(inputPath));
            }
        }

        return bytes;
    }

    void writeAllBytes(const fs::path& outputPath, const std::vector<Byte>& bytes, bool force)
    {
        const fs::path temporaryPath = prepareTemporaryOutputPath(outputPath, force);

        try
        {
            std::ofstream output(temporaryPath, std::ios::binary);
            if (!output)
            {
                throw std::runtime_error("Cannot create output file " + quotePath(temporaryPath));
            }

            if (!bytes.empty())
            {
                output.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
            }

            output.close();
            if (!output)
            {
                throw std::runtime_error("Cannot finalize output file " + quotePath(temporaryPath));
            }

            finalizeTemporaryOutput(temporaryPath, outputPath, force);
        }
        catch (...)
        {
            removeTemporaryOutput(temporaryPath);
            throw;
        }
    }

    unsigned int parseHexDigit(wchar_t value)
    {
        if (value >= L'0' && value <= L'9')
        {
            return static_cast<unsigned int>(value - L'0');
        }

        if (value >= L'a' && value <= L'f')
        {
            return static_cast<unsigned int>(value - L'a' + 10);
        }

        if (value >= L'A' && value <= L'F')
        {
            return static_cast<unsigned int>(value - L'A' + 10);
        }

        throw UsageError("IV must contain only hexadecimal characters");
    }

    std::array<Byte, IvSize> parseIvHex(std::wstring_view value)
    {
        std::wstring normalized;
        normalized.reserve(value.size());

        for (const wchar_t symbol : value)
        {
            if (std::iswspace(symbol) || symbol == L':' || symbol == L'-')
            {
                continue;
            }

            normalized.push_back(symbol);
        }

        if (normalized.size() != IvSize * 2)
        {
            throw UsageError("IV must contain exactly 16 hexadecimal characters");
        }

        std::array<Byte, IvSize> iv = {};
        for (std::size_t index = 0; index < IvSize; ++index)
        {
            const unsigned int high = parseHexDigit(normalized[index * 2]);
            const unsigned int low = parseHexDigit(normalized[index * 2 + 1]);
            iv[index] = static_cast<Byte>((high << 4u) | low);
        }

        return iv;
    }

    std::wstring ivToHex(const std::array<Byte, IvSize>& iv)
    {
        static constexpr wchar_t Digits[] = L"0123456789ABCDEF";

        std::wstring result;
        result.reserve(iv.size() * 2);

        for (const Byte byte : iv)
        {
            result.push_back(Digits[(byte >> 4u) & 0x0Fu]);
            result.push_back(Digits[byte & 0x0Fu]);
        }

        return result;
    }

    std::vector<Byte> bytesFromRawKeyText(const std::wstring& keyText)
    {
        if (keyText.empty())
        {
            throw std::runtime_error("Key cannot be empty");
        }

        std::string keyUtf8 = toUtf8(keyText);
        std::vector<Byte> keyBytes(keyUtf8.begin(), keyUtf8.end());
        SecureZeroMemory(keyUtf8.data(), keyUtf8.size());

        if (keyBytes.size() < blowfish::Blowfish::MinKeySize || keyBytes.size() > blowfish::Blowfish::MaxKeySize)
        {
            throw std::runtime_error("Raw key size must be from 4 to 56 bytes");
        }

        return keyBytes;
    }

    std::vector<Byte> padPkcs5(const std::vector<Byte>& input)
    {
        const std::size_t paddingLength = IvSize - (input.size() % IvSize);
        std::vector<Byte> output = input;
        output.insert(output.end(), paddingLength, static_cast<Byte>(paddingLength));
        return output;
    }

    std::vector<Byte> unpadPkcs5(const std::vector<Byte>& input)
    {
        if (input.empty() || (input.size() % IvSize) != 0)
        {
            throw std::runtime_error("CBC ciphertext size must be a non-zero multiple of 8 bytes");
        }

        const Byte paddingLength = input.back();
        if (paddingLength == 0 || paddingLength > IvSize || paddingLength > input.size())
        {
            throw std::runtime_error("Invalid PKCS5 padding");
        }

        const std::size_t start = input.size() - paddingLength;
        for (std::size_t index = start; index < input.size(); ++index)
        {
            if (input[index] != paddingLength)
            {
                throw std::runtime_error("Invalid PKCS5 padding");
            }
        }

        return std::vector<Byte>(input.begin(), input.begin() + static_cast<std::ptrdiff_t>(start));
    }

    std::array<Byte, IvSize> toBlock(std::span<const Byte> bytes)
    {
        if (bytes.size() != IvSize)
        {
            throw std::runtime_error("Internal block size mismatch");
        }

        std::array<Byte, IvSize> block = {};
        std::copy(bytes.begin(), bytes.end(), block.begin());
        return block;
    }

    void xorBlock(std::array<Byte, IvSize>& block, const std::array<Byte, IvSize>& other)
    {
        for (std::size_t index = 0; index < IvSize; ++index)
        {
            block[index] ^= other[index];
        }
    }

    std::vector<Byte> encryptCbc(
        const std::vector<Byte>& plainBytes,
        const std::vector<Byte>& keyBytes,
        const std::array<Byte, IvSize>& iv)
    {
        blowfish::Blowfish cipher(keyBytes);
        std::vector<Byte> paddedBytes = padPkcs5(plainBytes);
        std::vector<Byte> output(paddedBytes.size(), 0);
        std::array<Byte, IvSize> chain = iv;

        for (std::size_t offset = 0; offset < paddedBytes.size(); offset += IvSize)
        {
            std::array<Byte, IvSize> block = toBlock(std::span<const Byte>(paddedBytes.data() + offset, IvSize));
            xorBlock(block, chain);
            cipher.encryptBlock(block);
            std::copy(block.begin(), block.end(), output.begin() + static_cast<std::ptrdiff_t>(offset));
            chain = block;
        }

        return output;
    }

    std::vector<Byte> decryptCbc(
        const std::vector<Byte>& cipherBytes,
        const std::vector<Byte>& keyBytes,
        const std::array<Byte, IvSize>& iv)
    {
        if (cipherBytes.empty() || (cipherBytes.size() % IvSize) != 0)
        {
            throw std::runtime_error("CBC ciphertext size must be a non-zero multiple of 8 bytes");
        }

        blowfish::Blowfish cipher(keyBytes);
        std::vector<Byte> output(cipherBytes.size(), 0);
        std::array<Byte, IvSize> chain = iv;

        for (std::size_t offset = 0; offset < cipherBytes.size(); offset += IvSize)
        {
            const std::array<Byte, IvSize> currentCipherBlock =
                toBlock(std::span<const Byte>(cipherBytes.data() + offset, IvSize));

            std::array<Byte, IvSize> block = currentCipherBlock;
            cipher.decryptBlock(block);
            xorBlock(block, chain);
            std::copy(block.begin(), block.end(), output.begin() + static_cast<std::ptrdiff_t>(offset));
            chain = currentCipherBlock;
        }

        return unpadPkcs5(output);
    }

    std::vector<Byte> encryptCfb(
        const std::vector<Byte>& plainBytes,
        const std::vector<Byte>& keyBytes,
        const std::array<Byte, IvSize>& iv)
    {
        blowfish::Blowfish cipher(keyBytes);
        std::vector<Byte> output(plainBytes.size(), 0);
        std::array<Byte, IvSize> chain = iv;

        std::size_t offset = 0;
        while (offset < plainBytes.size())
        {
            std::array<Byte, IvSize> keystream = chain;
            cipher.encryptBlock(keystream);

            const std::size_t chunkSize = std::min<std::size_t>(IvSize, plainBytes.size() - offset);
            for (std::size_t index = 0; index < chunkSize; ++index)
            {
                output[offset + index] = plainBytes[offset + index] ^ keystream[index];
                chain[index] = output[offset + index];
            }

            offset += chunkSize;
        }

        return output;
    }

    std::vector<Byte> decryptCfb(
        const std::vector<Byte>& cipherBytes,
        const std::vector<Byte>& keyBytes,
        const std::array<Byte, IvSize>& iv)
    {
        blowfish::Blowfish cipher(keyBytes);
        std::vector<Byte> output(cipherBytes.size(), 0);
        std::array<Byte, IvSize> chain = iv;

        std::size_t offset = 0;
        while (offset < cipherBytes.size())
        {
            std::array<Byte, IvSize> keystream = chain;
            cipher.encryptBlock(keystream);

            const std::size_t chunkSize = std::min<std::size_t>(IvSize, cipherBytes.size() - offset);
            for (std::size_t index = 0; index < chunkSize; ++index)
            {
                output[offset + index] = cipherBytes[offset + index] ^ keystream[index];
                chain[index] = cipherBytes[offset + index];
            }

            offset += chunkSize;
        }

        return output;
    }

    std::vector<Byte> encryptPayload(
        const std::vector<Byte>& plainBytes,
        const std::vector<Byte>& keyBytes,
        const std::array<Byte, IvSize>& iv,
        CipherMode cipherMode)
    {
        if (cipherMode == CipherMode::Cbc)
        {
            return encryptCbc(plainBytes, keyBytes, iv);
        }

        return encryptCfb(plainBytes, keyBytes, iv);
    }

    std::vector<Byte> decryptPayload(
        const std::vector<Byte>& cipherBytes,
        const std::vector<Byte>& keyBytes,
        const std::array<Byte, IvSize>& iv,
        CipherMode cipherMode)
    {
        if (cipherMode == CipherMode::Cbc)
        {
            return decryptCbc(cipherBytes, keyBytes, iv);
        }

        return decryptCfb(cipherBytes, keyBytes, iv);
    }

    struct ParsedEncryptedFile
    {
        std::array<Byte, IvSize> iv = {};
        std::vector<Byte> cipherBytes;
    };

    ParsedEncryptedFile parseEncryptedFile(
        const std::vector<Byte>& fileBytes,
        CipherMode cipherMode,
        IvMode ivMode,
        std::wstring_view ivHex)
    {
        ParsedEncryptedFile result;

        if (ivMode == IvMode::Manual)
        {
            if (ivHex.empty())
            {
                throw UsageError("Manual IV mode requires --iv-hex <hex>");
            }

            result.iv = parseIvHex(ivHex);
            result.cipherBytes = fileBytes;
        }
        else if (ivMode == IvMode::Prefix)
        {
            if (fileBytes.size() < IvSize)
            {
                throw std::runtime_error("Input file is too short to contain IV");
            }

            std::copy_n(fileBytes.begin(), IvSize, result.iv.begin());
            result.cipherBytes.assign(fileBytes.begin() + static_cast<std::ptrdiff_t>(IvSize), fileBytes.end());
        }
        else
        {
            if (fileBytes.size() < IvSize)
            {
                throw std::runtime_error("Input file is too short to contain IV");
            }

            std::copy_n(fileBytes.end() - static_cast<std::ptrdiff_t>(IvSize), IvSize, result.iv.begin());
            result.cipherBytes.assign(fileBytes.begin(), fileBytes.end() - static_cast<std::ptrdiff_t>(IvSize));
        }

        if (cipherMode == CipherMode::Cbc && (result.cipherBytes.empty() || (result.cipherBytes.size() % IvSize) != 0))
        {
            throw std::runtime_error("CBC ciphertext size must be a non-zero multiple of 8 bytes");
        }

        return result;
    }

    std::vector<Byte> composeEncryptedFile(
        const std::vector<Byte>& cipherBytes,
        const std::array<Byte, IvSize>& iv,
        IvMode ivMode)
    {
        std::vector<Byte> output;
        output.reserve(cipherBytes.size() + (ivMode == IvMode::Manual ? 0 : IvSize));

        if (ivMode == IvMode::Prefix)
        {
            output.insert(output.end(), iv.begin(), iv.end());
        }

        output.insert(output.end(), cipherBytes.begin(), cipherBytes.end());

        if (ivMode == IvMode::Suffix)
        {
            output.insert(output.end(), iv.begin(), iv.end());
        }

        return output;
    }

    fs::path makeAutomaticOutputPath(const fs::path& inputPath, OperationMode operation)
    {
        if (operation == OperationMode::Encrypt)
        {
            fs::path outputPath = inputPath;
            outputPath += L".bf";
            return outputPath;
        }

        if (extensionEquals(inputPath, L".bf"))
        {
            fs::path outputPath = inputPath;
            outputPath.replace_extension(L"");
            return outputPath;
        }

        fs::path outputPath = inputPath;
        outputPath += L".ubf";
        return outputPath;
    }

    void showErrorMessage(const std::wstring& message)
    {
        MessageBoxW(nullptr, message.c_str(), L"Blowfish", MB_OK | MB_ICONERROR);
    }

    void showSuccessMessage(const fs::path& inputPath, const fs::path& outputPath)
    {
        std::wstring message = L"Операция завершена.\n\nВход:\n";
        message += inputPath.wstring();
        message += L"\n\nВыход:\n";
        message += outputPath.wstring();

        MessageBoxW(nullptr, message.c_str(), L"Blowfish", MB_OK | MB_ICONINFORMATION);
    }

    void setMode(Options& options, OperationMode operation)
    {
        if (options.operation != OperationMode::None && options.operation != operation)
        {
            throw UsageError("Only one mode can be specified");
        }

        options.operation = operation;
    }

    std::wstring nextArgument(int& index, int argc, wchar_t** argv, std::wstring_view optionName)
    {
        if (index + 1 >= argc)
        {
            throw UsageError("Missing value for " + toUtf8(optionName));
        }

        ++index;
        return argv[index];
    }

    CipherMode parseCipherMode(std::wstring value)
    {
        value = toLower(std::move(value));

        if (value == L"cbc")
        {
            return CipherMode::Cbc;
        }

        if (value == L"cfb")
        {
            return CipherMode::Cfb;
        }

        throw UsageError("Unsupported cipher mode. Use cbc or cfb");
    }

    IvMode parseIvMode(std::wstring value)
    {
        value = toLower(std::move(value));

        if (value == L"prefix")
        {
            return IvMode::Prefix;
        }

        if (value == L"suffix")
        {
            return IvMode::Suffix;
        }

        if (value == L"manual")
        {
            return IvMode::Manual;
        }

        throw UsageError("Unsupported IV mode. Use prefix, suffix, or manual");
    }

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
                setMode(options, OperationMode::Encrypt);
            }
            else if (argument == L"--decrypt")
            {
                setMode(options, OperationMode::Decrypt);
            }
            else if (argument == L"--shell-encrypt")
            {
                options.shellMode = true;
                setMode(options, OperationMode::Encrypt);
                options.inputPath = nextArgument(index, argc, argv, argument);
            }
            else if (argument == L"--shell-decrypt")
            {
                options.shellMode = true;
                setMode(options, OperationMode::Decrypt);
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
                options.keyText = nextArgument(index, argc, argv, argument);
            }
            else if (argument == L"--mode")
            {
                options.cipherMode = parseCipherMode(nextArgument(index, argc, argv, argument));
            }
            else if (argument == L"--iv-position")
            {
                options.ivMode = parseIvMode(nextArgument(index, argc, argv, argument));
            }
            else if (argument == L"--iv-hex")
            {
                options.ivHex = nextArgument(index, argc, argv, argument);
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

    void printHelp()
    {
        std::cout
            << "Blowfish\n\n"
            << toUtf8(L"Шифрование:\n")
            << "  Blowfish.exe --encrypt -i <file> -o <output> -k <key>\n"
            << "  Blowfish.exe --encrypt -i <file> -k <key> --mode cbc --iv-position prefix\n\n"
            << toUtf8(L"Расшифрование:\n")
            << "  Blowfish.exe --decrypt -i <file> -o <output> -k <key>\n"
            << "  Blowfish.exe --decrypt -i <file> -o <output> -k <key> --mode cbc --iv-position suffix\n"
            << "  Blowfish.exe --decrypt -i <file> -o <output> -k <key> --iv-position manual --iv-hex 0011223344556677\n\n"
            << toUtf8(L"Параметры:\n")
            << toUtf8(L"  --output         путь выходного файла (необязательно)\n")
            << toUtf8(L"  --force          перезаписывает существующий выходной файл\n")
            << toUtf8(L"  --key            raw key длиной от 4 до 56 байт\n")
            << toUtf8(L"  --mode           cbc | cfb (по умолчанию cbc)\n")
            << toUtf8(L"  --iv-position    prefix | suffix | manual (по умолчанию prefix)\n")
            << toUtf8(L"  --iv-hex         IV в hex, обязателен для manual\n")
            << toUtf8(L"  --help           показывает эту справку\n");
    }

    void setDefaultGuiFont(HWND handle)
    {
        SendMessageW(handle, WM_SETFONT, reinterpret_cast<WPARAM>(GetStockObject(DEFAULT_GUI_FONT)), TRUE);
    }

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

    void updateDialogIvControls(KeyDialogState& state, HWND windowHandle)
    {
        const bool manualIv = IsDlgButtonChecked(windowHandle, IvManualId) == BST_CHECKED;
        if (state.ivEditHandle != nullptr)
        {
            EnableWindow(state.ivEditHandle, manualIv ? TRUE : FALSE);
        }
    }

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

                createChildWindow(windowHandle, L"STATIC", L"Файл:", 0, 16, 16, 500, 18, FileStaticId);
                createChildWindow(windowHandle, L"STATIC", state->filePath, SS_LEFTNOWORDWRAP, 16, 36, 500, 18, FileStaticId + 1);
                createChildWindow(windowHandle, L"STATIC", L"Ключ:", 0, 16, 68, 500, 18, FileStaticId + 2);

                state->keyEditHandle = createChildWindow(
                    windowHandle,
                    L"EDIT",
                    state->keyText,
                    WS_BORDER | WS_TABSTOP | ES_PASSWORD | ES_AUTOHSCROLL,
                    16,
                    88,
                    500,
                    24,
                    KeyEditId);

                SendMessageW(state->keyEditHandle, EM_SETPASSWORDCHAR, L'*', 0);

                createChildWindow(windowHandle, L"BUTTON", L"Mode", BS_GROUPBOX, 16, 124, 240, 76, FileStaticId + 3);
                createChildWindow(windowHandle, L"BUTTON", L"CBC", WS_TABSTOP | BS_AUTORADIOBUTTON, 28, 148, 80, 18, ModeCbcId);
                createChildWindow(windowHandle, L"BUTTON", L"CFB", WS_TABSTOP | BS_AUTORADIOBUTTON, 28, 170, 80, 18, ModeCfbId);

                createChildWindow(windowHandle, L"BUTTON", L"IV Position", BS_GROUPBOX, 276, 124, 240, 110, FileStaticId + 4);
                createChildWindow(windowHandle, L"BUTTON", L"Prefix", WS_TABSTOP | BS_AUTORADIOBUTTON, 288, 148, 90, 18, IvPrefixId);
                createChildWindow(windowHandle, L"BUTTON", L"Suffix", WS_TABSTOP | BS_AUTORADIOBUTTON, 288, 170, 90, 18, IvSuffixId);
                createChildWindow(windowHandle, L"BUTTON", L"Manual", WS_TABSTOP | BS_AUTORADIOBUTTON, 288, 192, 90, 18, IvManualId);

                createChildWindow(windowHandle, L"STATIC", L"IV hex:", 0, 16, 214, 60, 18, FileStaticId + 5);
                state->ivEditHandle = createChildWindow(
                    windowHandle,
                    L"EDIT",
                    state->ivHex,
                    WS_BORDER | WS_TABSTOP | ES_AUTOHSCROLL,
                    76,
                    212,
                    440,
                    24,
                    IvEditId);

                createChildWindow(windowHandle, L"BUTTON", L"OK", WS_TABSTOP | BS_DEFPUSHBUTTON, 324, 252, 90, 28, IDOK);
                createChildWindow(windowHandle, L"BUTTON", L"Cancel", WS_TABSTOP | BS_PUSHBUTTON, 426, 252, 90, 28, IDCANCEL);

                CheckRadioButton(windowHandle, ModeCbcId, ModeCfbId, state->cipherMode == CipherMode::Cfb ? ModeCfbId : ModeCbcId);

                int checkedIvId = IvPrefixId;
                if (state->ivMode == IvMode::Suffix)
                {
                    checkedIvId = IvSuffixId;
                }
                else if (state->ivMode == IvMode::Manual)
                {
                    checkedIvId = IvManualId;
                }

                CheckRadioButton(windowHandle, IvPrefixId, IvManualId, checkedIvId);
                updateDialogIvControls(*state, windowHandle);

                SetFocus(state->keyEditHandle);
                return 0;
            }

            case WM_COMMAND:
            {
                const int commandId = LOWORD(wParam);

                if (commandId == IvPrefixId || commandId == IvSuffixId || commandId == IvManualId)
                {
                    if (state != nullptr)
                    {
                        updateDialogIvControls(*state, windowHandle);
                    }

                    return 0;
                }

                if (commandId == IDOK)
                {
                    if (state == nullptr || state->keyEditHandle == nullptr || state->ivEditHandle == nullptr)
                    {
                        DestroyWindow(windowHandle);
                        return 0;
                    }

                    const int keyLength = GetWindowTextLengthW(state->keyEditHandle);
                    std::wstring keyText(static_cast<std::size_t>(keyLength) + 1, L'\0');
                    GetWindowTextW(state->keyEditHandle, keyText.data(), keyLength + 1);
                    keyText.resize(static_cast<std::size_t>(keyLength));

                    if (keyText.empty())
                    {
                        MessageBoxW(windowHandle, L"Ключ не может быть пустым.", state->title.c_str(), MB_OK | MB_ICONERROR);
                        return 0;
                    }

                    const int ivLength = GetWindowTextLengthW(state->ivEditHandle);
                    std::wstring ivHex(static_cast<std::size_t>(ivLength) + 1, L'\0');
                    GetWindowTextW(state->ivEditHandle, ivHex.data(), ivLength + 1);
                    ivHex.resize(static_cast<std::size_t>(ivLength));

                    state->keyText = std::move(keyText);
                    state->ivHex = std::move(ivHex);
                    state->cipherMode = IsDlgButtonChecked(windowHandle, ModeCfbId) == BST_CHECKED
                        ? CipherMode::Cfb
                        : CipherMode::Cbc;

                    if (IsDlgButtonChecked(windowHandle, IvManualId) == BST_CHECKED)
                    {
                        state->ivMode = IvMode::Manual;
                    }
                    else if (IsDlgButtonChecked(windowHandle, IvSuffixId) == BST_CHECKED)
                    {
                        state->ivMode = IvMode::Suffix;
                    }
                    else
                    {
                        state->ivMode = IvMode::Prefix;
                    }

                    if (state->ivMode == IvMode::Manual)
                    {
                        try
                        {
                            static_cast<void>(parseIvHex(state->ivHex));
                        }
                        catch (const std::exception& exception)
                        {
                            MessageBoxW(windowHandle, fromUtf8(exception.what()).c_str(), state->title.c_str(), MB_OK | MB_ICONERROR);
                            return 0;
                        }
                    }

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

    bool promptOptionsWithDialog(const std::wstring& title, const fs::path& inputPath, Options& options)
    {
        registerKeyDialogClass();

        RECT workArea = {};
        SystemParametersInfoW(SPI_GETWORKAREA, 0, &workArea, 0);

        constexpr int width = 550;
        constexpr int height = 340;
        const int x = workArea.left + ((workArea.right - workArea.left) - width) / 2;
        const int y = workArea.top + ((workArea.bottom - workArea.top) - height) / 2;

        KeyDialogState state;
        state.title = title;
        state.filePath = inputPath.wstring();
        state.keyText = options.keyText;
        state.ivHex = options.ivHex;
        state.cipherMode = options.cipherMode;
        state.ivMode = options.ivMode;

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

        if (!state.accepted)
        {
            return false;
        }

        options.keyText = std::move(state.keyText);
        options.ivHex = std::move(state.ivHex);
        options.cipherMode = state.cipherMode;
        options.ivMode = state.ivMode;
        return true;
    }

    void executeEncrypt(const Options& options)
    {
        validateFilePaths(options.inputPath, options.outputPath, options.force);

        std::vector<Byte> keyBytes = bytesFromRawKeyText(options.keyText);
        std::vector<Byte> plainBytes = readAllBytes(options.inputPath);

        const std::array<Byte, IvSize> iv = options.ivHex.empty()
            ? randomBytes<IvSize>()
            : parseIvHex(options.ivHex);

        const std::vector<Byte> cipherBytes = encryptPayload(plainBytes, keyBytes, iv, options.cipherMode);
        const std::vector<Byte> outputBytes = composeEncryptedFile(cipherBytes, iv, options.ivMode);

        writeAllBytes(options.outputPath, outputBytes, options.force);

        SecureZeroMemory(keyBytes.data(), keyBytes.size());
    }

    void executeDecrypt(const Options& options)
    {
        validateFilePaths(options.inputPath, options.outputPath, options.force);

        std::vector<Byte> keyBytes = bytesFromRawKeyText(options.keyText);
        const std::vector<Byte> fileBytes = readAllBytes(options.inputPath);
        const ParsedEncryptedFile parsed = parseEncryptedFile(fileBytes, options.cipherMode, options.ivMode, options.ivHex);
        const std::vector<Byte> plainBytes = decryptPayload(parsed.cipherBytes, keyBytes, parsed.iv, options.cipherMode);

        writeAllBytes(options.outputPath, plainBytes, options.force);

        SecureZeroMemory(keyBytes.data(), keyBytes.size());
    }

    int executeShellMode(Options& options)
    {
        options.outputPath = makeAutomaticOutputPath(options.inputPath, options.operation);

        const std::wstring title = options.operation == OperationMode::Encrypt
            ? L"Blowfish Encrypt"
            : L"Blowfish Decrypt";

        if (!promptOptionsWithDialog(title, options.inputPath, options))
        {
            return 2;
        }

        if (options.operation == OperationMode::Encrypt)
        {
            executeEncrypt(options);
        }
        else
        {
            executeDecrypt(options);
        }

        if (!options.keyText.empty())
        {
            SecureZeroMemory(options.keyText.data(), options.keyText.size() * sizeof(wchar_t));
        }

        showSuccessMessage(options.inputPath, options.outputPath);
        return 0;
    }

    int executeConsoleMode(Options& options)
    {
        if (options.outputPath.empty())
        {
            options.outputPath = makeAutomaticOutputPath(options.inputPath, options.operation);
        }

        if (options.keyText.empty())
        {
            throw UsageError("Key is required. Use --key <value>");
        }

        if (options.ivMode == IvMode::Manual && options.ivHex.empty())
        {
            throw UsageError("Manual IV mode requires --iv-hex <hex>");
        }

        if (options.operation == OperationMode::Encrypt)
        {
            executeEncrypt(options);
        }
        else
        {
            executeDecrypt(options);
        }

        SecureZeroMemory(options.keyText.data(), options.keyText.size() * sizeof(wchar_t));
        std::wcout << L"Готово: " << options.outputPath.wstring() << L"\n";
        return 0;
    }

    int execute(Options& options)
    {
        if (options.help)
        {
            printHelp();
            return 0;
        }

        if (options.operation == OperationMode::None)
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

int wmain(int argc, wchar_t** argv)
{
    configureConsole();

    Options options;

    try
    {
        blowfish::Blowfish::selfTest();
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
