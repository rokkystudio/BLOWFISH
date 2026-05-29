#pragma once

#include "crypto_types.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>

namespace blowfish_tool
{
    /**
     * Реализует блочный шифр Blowfish с 16 раундами и 64-битным блоком.
     */
    class Blowfish
    {
    public:
        static constexpr std::size_t BlockSize = 8;
        static constexpr std::size_t MinKeySize = 4;
        static constexpr std::size_t MaxKeySize = 56;

        explicit Blowfish(std::span<const Byte> key);

        /**
         * Шифрует один 64-битный блок на месте.
         */
        void encryptBlock(std::array<Byte, BlockSize>& block) const;

        /**
         * Расшифровывает один 64-битный блок на месте.
         */
        void decryptBlock(std::array<Byte, BlockSize>& block) const;

        /**
         * Проверяет реализацию Blowfish по тестовому вектору ECB.
         */
        static void selfTest();

    private:
        std::uint32_t f(std::uint32_t value) const;
        void encryptWords(std::uint32_t& left, std::uint32_t& right) const;
        void decryptWords(std::uint32_t& left, std::uint32_t& right) const;

        std::array<std::uint32_t, 18> p_ = {};
        std::array<std::array<std::uint32_t, 256>, 4> s_ = {};
    };
}