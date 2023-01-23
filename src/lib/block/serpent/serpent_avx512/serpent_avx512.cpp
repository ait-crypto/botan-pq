/*
* (C) 2023 Jack Lloyd
*
* Botan is released under the Simplified BSD License (see license.txt)
*/

#include <botan/internal/serpent.h>
#include <botan/internal/simd_avx512.h>
#include <botan/internal/serpent_sbox.h>

namespace Botan {

template<uint8_t I0, uint8_t I1, uint8_t I2, uint8_t I3,
         uint8_t I4, uint8_t I5, uint8_t I6, uint8_t I7>
BOTAN_FORCE_INLINE
void SBOX_AVX512(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   auto t0a = SIMD_16x32::ternary_fn<I0>(a, b, c);
   auto t0b = SIMD_16x32::ternary_fn<I2>(a, b, c);
   auto t0c = SIMD_16x32::ternary_fn<I4>(a, b, c);
   auto t0d = SIMD_16x32::ternary_fn<I6>(a, b, c);

   auto t1a = SIMD_16x32::ternary_fn<I1>(a, b, c);
   auto t1b = SIMD_16x32::ternary_fn<I3>(a, b, c);
   auto t1c = SIMD_16x32::ternary_fn<I5>(a, b, c);
   auto t1d = SIMD_16x32::ternary_fn<I7>(a, b, c);

   a = SIMD_16x32::choose(d, t1a, t0a);
   b = SIMD_16x32::choose(d, t1b, t0b);
   c = SIMD_16x32::choose(d, t1c, t0c);
   d = SIMD_16x32::choose(d, t1d, t0d);
   }

BOTAN_FORCE_INLINE
void SBoxE0(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   SBOX_AVX512<0xCD, 0x1A, 0xA7, 0x43, 0x2C, 0x97, 0x96, 0x99>(a, b, c, d);
   }

BOTAN_FORCE_INLINE
void SBoxE1(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   SBOX_AVX512<0x4B, 0x39, 0xC5, 0x1E, 0x59, 0xA6, 0x93, 0x74>(a, b, c, d);
   }

BOTAN_FORCE_INLINE
void SBoxE2(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   SBOX_AVX512<0xC6, 0x39, 0x9E, 0xA4, 0xB4, 0x4D, 0xE9, 0x25>(a, b, c, d);
   }

BOTAN_FORCE_INLINE
void SBoxE3(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   SBOX_AVX512<0xB4, 0x39, 0x9C, 0xA6, 0x1A, 0xE9, 0x76, 0x83>(a, b, c, d);
   }

BOTAN_FORCE_INLINE
void SBoxE4(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   SBOX_AVX512<0x59, 0x9A, 0xD8, 0x69, 0x92, 0xBC, 0x1E, 0xE2>(a, b, c, d);
   }

BOTAN_FORCE_INLINE
void SBoxE5(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   SBOX_AVX512<0x59, 0x9A, 0x65, 0x3C, 0x93, 0x2E, 0xE9, 0x46>(a, b, c, d);
   }

BOTAN_FORCE_INLINE
void SBoxE6(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   SBOX_AVX512<0xC1, 0x76, 0x99, 0x69, 0x6D, 0x43, 0x86, 0x5B>(a, b, c, d);
   }

BOTAN_FORCE_INLINE
void SBoxE7(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   SBOX_AVX512<0x95, 0x2B, 0x8E, 0xE1, 0x16, 0x9D, 0xB6, 0x46>(a, b, c, d);
   }

BOTAN_FORCE_INLINE
void SBoxD0(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   SBOX_AVX512<0x1D, 0x63, 0x36, 0xD2, 0xA9, 0x56, 0x87, 0x3A>(a, b, c, d);
   }

BOTAN_FORCE_INLINE
void SBoxD1(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   SBOX_AVX512<0x83, 0x67, 0xE6, 0x0D, 0x6B, 0x34, 0x5A, 0x69>(a, b, c, d);
   }

BOTAN_FORCE_INLINE
void SBoxD2(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   SBOX_AVX512<0x1E, 0xD2, 0xA6, 0x9C, 0x65, 0xC6, 0x37, 0x68>(a, b, c, d);
   }

BOTAN_FORCE_INLINE
void SBoxD3(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   SBOX_AVX512<0xD2, 0x99, 0x6E, 0x49, 0xE8, 0x1E, 0xB6, 0x2C>(a, b, c, d);
   }

BOTAN_FORCE_INLINE
void SBoxD4(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   SBOX_AVX512<0x69, 0xAC, 0xCA, 0x65, 0x89, 0x7A, 0xA6, 0x3C>(a, b, c, d);
   }

BOTAN_FORCE_INLINE
void SBoxD5(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   SBOX_AVX512<0x78, 0x47, 0x94, 0x5B, 0x9A, 0x36, 0xD9, 0x29>(a, b, c, d);
   }

BOTAN_FORCE_INLINE
void SBoxD6(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   SBOX_AVX512<0x67, 0xD0, 0x39, 0xC6, 0x4B, 0x65, 0x51, 0xBC>(a, b, c, d);
   }

BOTAN_FORCE_INLINE
void SBoxD7(SIMD_16x32& a, SIMD_16x32& b, SIMD_16x32& c, SIMD_16x32& d)
   {
   SBOX_AVX512<0x4B, 0x65, 0x2D, 0xC6, 0x6C, 0x59, 0xEA, 0x16>(a, b, c, d);
   }

BOTAN_AVX512_FN
void Serpent::avx512_encrypt_16(const uint8_t in[16*16], uint8_t out[16*16]) const
   {
   using namespace Botan::Serpent_F;

   SIMD_16x32 B0 = SIMD_16x32::load_le(in);
   SIMD_16x32 B1 = SIMD_16x32::load_le(in + 64);
   SIMD_16x32 B2 = SIMD_16x32::load_le(in + 128);
   SIMD_16x32 B3 = SIMD_16x32::load_le(in + 192);

   SIMD_16x32::transpose(B0, B1, B2, B3);

   const Key_Inserter key_xor(m_round_key.data());

   key_xor( 0,B0,B1,B2,B3); SBoxE0(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 1,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 2,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 3,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 4,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 5,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 6,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 7,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);

   key_xor( 8,B0,B1,B2,B3); SBoxE0(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor( 9,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(10,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(11,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(12,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(13,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(14,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(15,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);

   key_xor(16,B0,B1,B2,B3); SBoxE0(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(17,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(18,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(19,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(20,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(21,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(22,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(23,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); transform(B0,B1,B2,B3);

   key_xor(24,B0,B1,B2,B3); SBoxE0(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(25,B0,B1,B2,B3); SBoxE1(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(26,B0,B1,B2,B3); SBoxE2(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(27,B0,B1,B2,B3); SBoxE3(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(28,B0,B1,B2,B3); SBoxE4(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(29,B0,B1,B2,B3); SBoxE5(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(30,B0,B1,B2,B3); SBoxE6(B0,B1,B2,B3); transform(B0,B1,B2,B3);
   key_xor(31,B0,B1,B2,B3); SBoxE7(B0,B1,B2,B3); key_xor(32,B0,B1,B2,B3);

   SIMD_16x32::transpose(B0, B1, B2, B3);
   B0.store_le(out);
   B1.store_le(out + 64);
   B2.store_le(out + 128);
   B3.store_le(out + 192);

   SIMD_16x32::zero_registers();
   }

BOTAN_AVX512_FN
void Serpent::avx512_decrypt_16(const uint8_t in[16*16], uint8_t out[16*16]) const
   {
   using namespace Botan::Serpent_F;

   SIMD_16x32 B0 = SIMD_16x32::load_le(in);
   SIMD_16x32 B1 = SIMD_16x32::load_le(in + 64);
   SIMD_16x32 B2 = SIMD_16x32::load_le(in + 128);
   SIMD_16x32 B3 = SIMD_16x32::load_le(in + 192);

   SIMD_16x32::transpose(B0, B1, B2, B3);

   const Key_Inserter key_xor(m_round_key.data());

   key_xor(32,B0,B1,B2,B3);  SBoxD7(B0,B1,B2,B3); key_xor(31,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor(30,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor(29,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor(28,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor(27,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor(26,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor(25,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD0(B0,B1,B2,B3); key_xor(24,B0,B1,B2,B3);

   i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor(23,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor(22,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor(21,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor(20,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor(19,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor(18,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor(17,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD0(B0,B1,B2,B3); key_xor(16,B0,B1,B2,B3);

   i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor(15,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor(14,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor(13,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor(12,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor(11,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor(10,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor( 9,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD0(B0,B1,B2,B3); key_xor( 8,B0,B1,B2,B3);

   i_transform(B0,B1,B2,B3); SBoxD7(B0,B1,B2,B3); key_xor( 7,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD6(B0,B1,B2,B3); key_xor( 6,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD5(B0,B1,B2,B3); key_xor( 5,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD4(B0,B1,B2,B3); key_xor( 4,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD3(B0,B1,B2,B3); key_xor( 3,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD2(B0,B1,B2,B3); key_xor( 2,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD1(B0,B1,B2,B3); key_xor( 1,B0,B1,B2,B3);
   i_transform(B0,B1,B2,B3); SBoxD0(B0,B1,B2,B3); key_xor( 0,B0,B1,B2,B3);

   SIMD_16x32::transpose(B0, B1, B2, B3);

   B0.store_le(out);
   B1.store_le(out + 64);
   B2.store_le(out + 128);
   B3.store_le(out + 192);

   SIMD_16x32::zero_registers();
   }

}
