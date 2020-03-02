/*
 * NTDLL bitmap functions
 *
 * Copyright 2002 Jon Griffiths
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301, USA
 *
 * NOTES
 *  Bitmaps are an efficient type for manipulating large arrays of bits. They
 *  are commonly used by device drivers (e.g. For holding dirty/free blocks),
 *  but are also available to applications that need this functionality.
 *
 *  Bits are set LSB to MSB in each consecutive byte, making this implementation
 *  binary compatible with Win32.
 *
 *  Note that to avoid unexpected behaviour, the size of a bitmap should be set
 *  to a multiple of 32.
 */
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdbool.h>
#include <search.h>

#include "winnt_types.h"
#include "pe_linker.h"
#include "ntoskernel.h"
#include "log.h"
#include "winexports.h"
#include "util.h"

#define TRACE DebugLog
#define FIXME DebugLog

/* Bits set from LSB to MSB; used as mask for runs < 8 bits */
static const BYTE NTDLL_maskBits[8] = { 0, 1, 3, 7, 15, 31, 63, 127 };

/* Number of set bits for each value of a nibble; used for counting */
static const BYTE NTDLL_nibbleBitCount[16] = {
  0, 1, 1, 2, 1, 2, 2, 3, 1, 2, 2, 3, 2, 3, 3, 4
};

/* First set bit in a nibble; used for determining least significant bit */
static const BYTE NTDLL_leastSignificant[16] = {
  0, 0, 1, 0, 2, 0, 1, 0, 3, 0, 1, 0, 2, 0, 1, 0
};

/* Last set bit in a nibble; used for determining most significant bit */
static const signed char NTDLL_mostSignificant[16] = {
  -1, 0, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 3, 3, 3, 3
};

/*************************************************************************
 * RtlInitializeBitMap	[NTDLL.@]
 *
 * Initialise a new bitmap.
 *
 * PARAMS
 *  lpBits [I] Bitmap pointer
 *  lpBuff [I] Memory for the bitmap
 *  ulSize [I] Size of lpBuff in bits
 *
 * RETURNS
 *  Nothing.
 *
 * NOTES
 *  lpBuff must be aligned on a ULONG suitable boundary, to a multiple of 32 bytes
 *  in size (irrespective of ulSize given).
 */
VOID WINAPI RtlInitializeBitMap(PRTL_BITMAP lpBits, PULONG lpBuff, ULONG ulSize)
{
  TRACE("(%p,%p,%u)\n", lpBits,lpBuff,ulSize);
  lpBits->SizeOfBitMap = ulSize;
  lpBits->Buffer = (PVOID) lpBuff;
}

/*************************************************************************
 * RtlSetAllBits	[NTDLL.@]
 *
 * Set all bits in a bitmap.
 *
 * PARAMS
 *  lpBits [I] Bitmap pointer
 *
 * RETURNS
 *  Nothing.
 */
VOID WINAPI RtlSetAllBits(PRTL_BITMAP lpBits)
{
  TRACE("(%p)\n", lpBits);
  memset(lpBits->Buffer, 0xff, ((lpBits->SizeOfBitMap + 31) & ~31) >> 3);
}

/*************************************************************************
 * RtlClearAllBits	[NTDLL.@]
 *
 * Clear all bits in a bitmap.
 *
 * PARAMS
 *  lpBit [I] Bitmap pointer
 *
 * RETURNS
 *  Nothing.
 */
VOID WINAPI RtlClearAllBits(PRTL_BITMAP lpBits)
{
  TRACE("(%p)\n", lpBits);
  memset(lpBits->Buffer, 0, ((lpBits->SizeOfBitMap + 31) & ~31) >> 3);
}

/*************************************************************************
 * RtlSetBits	[NTDLL.@]
 *
 * Set a range of bits in a bitmap.
 *
 * PARAMS
 *  lpBits  [I] Bitmap pointer
 *  ulStart [I] First bit to set
 *  ulCount [I] Number of consecutive bits to set
 *
 * RETURNS
 *  Nothing.
 */
VOID WINAPI RtlSetBits(PRTL_BITMAP lpBits, ULONG ulStart, ULONG ulCount)
{
  LPBYTE lpOut;

  TRACE("(%p,%u,%u)\n", lpBits, ulStart, ulCount);

  if (!lpBits || !ulCount ||
      ulStart >= lpBits->SizeOfBitMap ||
      ulCount > lpBits->SizeOfBitMap - ulStart)
    return;

  /* FIXME: It might be more efficient/cleaner to manipulate four bytes
   * at a time. But beware of the pointer arithmetics...
   */
  lpOut = ((BYTE*)lpBits->Buffer) + (ulStart >> 3u);

  /* Set bits in first byte, if ulStart isn't a byte boundary */
  if (ulStart & 7)
  {
    if (ulCount > 7)
    {
      /* Set from start bit to the end of the byte */
      *lpOut++ |= 0xff << (ulStart & 7);
      ulCount -= (8 - (ulStart & 7));
    }
    else
    {
      /* Set from the start bit, possibly into the next byte also */
      USHORT initialWord = NTDLL_maskBits[ulCount] << (ulStart & 7);

      *lpOut |= (initialWord & 0xff);
      if (initialWord >> 8) lpOut[1] |= (initialWord >> 8);
      return;
    }
  }

  /* Set bits up to complete byte count */
  if (ulCount >> 3)
  {
    memset(lpOut, 0xff, ulCount >> 3);
    lpOut = lpOut + (ulCount >> 3);
  }

  /* Set remaining bits, if any */
  if (ulCount & 0x7)
    *lpOut |= NTDLL_maskBits[ulCount & 0x7];
}

/*************************************************************************
 * RtlClearBits	[NTDLL.@]
 *
 * Clear bits in a bitmap.
 *
 * PARAMS
 *  lpBits  [I] Bitmap pointer
 *  ulStart [I] First bit to set
 *  ulCount [I] Number of consecutive bits to clear
 *
 * RETURNS
 *  Nothing.
 */
VOID WINAPI RtlClearBits(PRTL_BITMAP lpBits, ULONG ulStart, ULONG ulCount)
{
  LPBYTE lpOut;

  TRACE("(%p,%u,%u)\n", lpBits, ulStart, ulCount);

  if (!lpBits || !ulCount ||
      ulStart >= lpBits->SizeOfBitMap ||
      ulCount > lpBits->SizeOfBitMap - ulStart)
    return;

  /* FIXME: It might be more efficient/cleaner to manipulate four bytes
   * at a time. But beware of the pointer arithmetics...
   */
  lpOut = ((BYTE*)lpBits->Buffer) + (ulStart >> 3u);

  /* Clear bits in first byte, if ulStart isn't a byte boundary */
  if (ulStart & 7)
  {
    if (ulCount > 7)
    {
      /* Clear from start bit to the end of the byte */
      *lpOut++ &= ~(0xff << (ulStart & 7));
      ulCount -= (8 - (ulStart & 7));
    }
    else
    {
      /* Clear from the start bit, possibly into the next byte also */
      USHORT initialWord = ~(NTDLL_maskBits[ulCount] << (ulStart & 7));

      *lpOut &= (initialWord & 0xff);
      if ((initialWord >> 8) != 0xff) lpOut[1] &= (initialWord >> 8);
      return;
    }
  }

  /* Clear bits (in blocks of 8) on whole byte boundaries */
  if (ulCount >> 3)
  {
    memset(lpOut, 0, ulCount >> 3);
    lpOut = lpOut + (ulCount >> 3);
  }

  /* Clear remaining bits, if any */
  if (ulCount & 0x7)
    *lpOut &= ~NTDLL_maskBits[ulCount & 0x7];
}

/*************************************************************************
 * RtlAreBitsSet	[NTDLL.@]
 *
 * Determine if part of a bitmap is set.
 *
 * PARAMS
 *  lpBits  [I] Bitmap pointer
 *  ulStart [I] First bit to check from
 *  ulCount [I] Number of consecutive bits to check
 *
 * RETURNS
 *  TRUE,  If ulCount bits from ulStart are set.
 *  FALSE, Otherwise.
 */
BOOLEAN WINAPI RtlAreBitsSet(PCRTL_BITMAP lpBits, ULONG ulStart, ULONG ulCount)
{
  LPBYTE lpOut;
  ULONG ulRemainder;

  TRACE("(%p,%u,%u)\n", lpBits, ulStart, ulCount);

  if (!lpBits || !ulCount ||
      ulStart >= lpBits->SizeOfBitMap ||
      ulCount > lpBits->SizeOfBitMap - ulStart)
    return FALSE;

  /* FIXME: It might be more efficient/cleaner to manipulate four bytes
   * at a time. But beware of the pointer arithmetics...
   */
  lpOut = ((BYTE*)lpBits->Buffer) + (ulStart >> 3u);

  /* Check bits in first byte, if ulStart isn't a byte boundary */
  if (ulStart & 7)
  {
    if (ulCount > 7)
    {
      /* Check from start bit to the end of the byte */
      if ((*lpOut &
          ((0xff << (ulStart & 7))) & 0xff) != ((0xff << (ulStart & 7) & 0xff)))
        return FALSE;
      lpOut++;
      ulCount -= (8 - (ulStart & 7));
    }
    else
    {
      /* Check from the start bit, possibly into the next byte also */
      USHORT initialWord = NTDLL_maskBits[ulCount] << (ulStart & 7);

      if ((*lpOut & (initialWord & 0xff)) != (initialWord & 0xff))
        return FALSE;
      if ((initialWord & 0xff00) &&
          ((lpOut[1] & (initialWord >> 8)) != (initialWord >> 8)))
        return FALSE;
      return TRUE;
    }
  }

  /* Check bits in blocks of 8 bytes */
  ulRemainder = ulCount & 7;
  ulCount >>= 3;
  while (ulCount--)
  {
    if (*lpOut++ != 0xff)
      return FALSE;
  }

  /* Check remaining bits, if any */
  if (ulRemainder &&
      (*lpOut & NTDLL_maskBits[ulRemainder]) != NTDLL_maskBits[ulRemainder])
    return FALSE;
  return TRUE;
}

/*************************************************************************
 * RtlAreBitsClear	[NTDLL.@]
 *
 * Determine if part of a bitmap is clear.
 *
 * PARAMS
 *  lpBits  [I] Bitmap pointer
 *  ulStart [I] First bit to check from
 *  ulCount [I] Number of consecutive bits to check
 *
 * RETURNS
 *  TRUE,  If ulCount bits from ulStart are clear.
 *  FALSE, Otherwise.
 */
BOOLEAN WINAPI RtlAreBitsClear(PCRTL_BITMAP lpBits, ULONG ulStart, ULONG ulCount)
{
  LPBYTE lpOut;
  ULONG ulRemainder;

  TRACE("(%p,%u,%u)\n", lpBits, ulStart, ulCount);

  if (!lpBits || !ulCount ||
      ulStart >= lpBits->SizeOfBitMap ||
      ulCount > lpBits->SizeOfBitMap - ulStart)
    return FALSE;

  /* FIXME: It might be more efficient/cleaner to manipulate four bytes
   * at a time. But beware of the pointer arithmetics...
   */
  lpOut = ((BYTE*)lpBits->Buffer) + (ulStart >> 3u);

  /* Check bits in first byte, if ulStart isn't a byte boundary */
  if (ulStart & 7)
  {
    if (ulCount > 7)
    {
      /* Check from start bit to the end of the byte */
      if (*lpOut & ((0xff << (ulStart & 7)) & 0xff))
        return FALSE;
      lpOut++;
      ulCount -= (8 - (ulStart & 7));
    }
    else
    {
      /* Check from the start bit, possibly into the next byte also */
      USHORT initialWord = NTDLL_maskBits[ulCount] << (ulStart & 7);

      if (*lpOut & (initialWord & 0xff))
        return FALSE;
      if ((initialWord & 0xff00) && (lpOut[1] & (initialWord >> 8)))
        return FALSE;
      return TRUE;
    }
  }

  /* Check bits in blocks of 8 bytes */
  ulRemainder = ulCount & 7;
  ulCount >>= 3;
  while (ulCount--)
  {
    if (*lpOut++)
      return FALSE;
  }

  /* Check remaining bits, if any */
  if (ulRemainder && *lpOut & NTDLL_maskBits[ulRemainder])
    return FALSE;
  return TRUE;
}

/*************************************************************************
 * RtlFindSetBits	[NTDLL.@]
 *
 * Find a block of set bits in a bitmap.
 *
 * PARAMS
 *  lpBits  [I] Bitmap pointer
 *  ulCount [I] Number of consecutive set bits to find
 *  ulHint  [I] Suggested starting position for set bits
 *
 * RETURNS
 *  The bit at which the match was found, or -1 if no match was found.
 */
ULONG WINAPI RtlFindSetBits(PCRTL_BITMAP lpBits, ULONG ulCount, ULONG ulHint)
{
  ULONG ulPos, ulEnd;

  TRACE("(%p,%u,%u)\n", lpBits, ulCount, ulHint);

  if (!lpBits || !ulCount || ulCount > lpBits->SizeOfBitMap)
    return ~0U;

  ulEnd = lpBits->SizeOfBitMap;

  if (ulHint + ulCount > lpBits->SizeOfBitMap)
    ulHint = 0;

  ulPos = ulHint;

  while (ulPos < ulEnd)
  {
    /* FIXME: This could be made a _lot_ more efficient */
    if (RtlAreBitsSet(lpBits, ulPos, ulCount))
      return ulPos;

    /* Start from the beginning if we hit the end and had a hint */
    if (ulPos == ulEnd - 1 && ulHint)
    {
      ulEnd = ulHint;
      ulPos = ulHint = 0;
    }
    else
      ulPos++;
  }
  return ~0U;
}

/*************************************************************************
 * RtlFindClearBits	[NTDLL.@]
 *
 * Find a block of clear bits in a bitmap.
 *
 * PARAMS
 *  lpBits  [I] Bitmap pointer
 *  ulCount [I] Number of consecutive clear bits to find
 *  ulHint  [I] Suggested starting position for clear bits
 *
 * RETURNS
 *  The bit at which the match was found, or -1 if no match was found.
 */
ULONG WINAPI RtlFindClearBits(PCRTL_BITMAP lpBits, ULONG ulCount, ULONG ulHint)
{
  ULONG ulPos, ulEnd;

  TRACE("(%p,%u,%u)\n", lpBits, ulCount, ulHint);

  if (!lpBits || !ulCount || ulCount > lpBits->SizeOfBitMap)
    return ~0U;

  ulEnd = lpBits->SizeOfBitMap;

  if (ulHint + ulCount > lpBits->SizeOfBitMap)
    ulHint = 0;

  ulPos = ulHint;

  while (ulPos < ulEnd)
  {
    /* FIXME: This could be made a _lot_ more efficient */
    if (RtlAreBitsClear(lpBits, ulPos, ulCount))
      return ulPos;

    /* Start from the beginning if we hit the end and started from ulHint */
    if (ulPos == ulEnd - 1 && ulHint)
    {
      ulEnd = ulHint;
      ulPos = ulHint = 0;
    }
    else
      ulPos++;
  }
  return ~0U;
}

/*************************************************************************
 * RtlFindSetBitsAndClear	[NTDLL.@]
 *
 * Find a block of set bits in a bitmap, and clear them if found.
 *
 * PARAMS
 *  lpBits  [I] Bitmap pointer
 *  ulCount [I] Number of consecutive set bits to find
 *  ulHint  [I] Suggested starting position for set bits
 *
 * RETURNS
 *  The bit at which the match was found, or -1 if no match was found.
 */
ULONG WINAPI RtlFindSetBitsAndClear(PRTL_BITMAP lpBits, ULONG ulCount, ULONG ulHint)
{
  ULONG ulPos;

  TRACE("(%p,%u,%u)\n", lpBits, ulCount, ulHint);

  ulPos = RtlFindSetBits(lpBits, ulCount, ulHint);
  if (ulPos != ~0U)
    RtlClearBits(lpBits, ulPos, ulCount);
  return ulPos;
}

/*************************************************************************
 * RtlFindClearBitsAndSet	[NTDLL.@]
 *
 * Find a block of clear bits in a bitmap, and set them if found.
 *
 * PARAMS
 *  lpBits  [I] Bitmap pointer
 *  ulCount [I] Number of consecutive clear bits to find
 *  ulHint  [I] Suggested starting position for clear bits
 *
 * RETURNS
 *  The bit at which the match was found, or -1 if no match was found.
 */
ULONG WINAPI RtlFindClearBitsAndSet(PRTL_BITMAP lpBits, ULONG ulCount, ULONG ulHint)
{
  ULONG ulPos;

  TRACE("(%p,%u,%u)\n", lpBits, ulCount, ulHint);

  ulPos = RtlFindClearBits(lpBits, ulCount, ulHint);
  if (ulPos != ~0U)
    RtlSetBits(lpBits, ulPos, ulCount);
  return ulPos;
}

/*************************************************************************
 * RtlNumberOfSetBits	[NTDLL.@]
 *
 * Find the number of set bits in a bitmap.
 *
 * PARAMS
 *  lpBits [I] Bitmap pointer
 *
 * RETURNS
 *  The number of set bits.
 */
ULONG WINAPI RtlNumberOfSetBits(PCRTL_BITMAP lpBits)
{
  ULONG ulSet = 0;

  TRACE("(%p)\n", lpBits);

  if (lpBits)
  {
    LPBYTE lpOut = (BYTE *)lpBits->Buffer;
    ULONG ulCount, ulRemainder;
    BYTE bMasked;

    ulCount = lpBits->SizeOfBitMap >> 3;
    ulRemainder = lpBits->SizeOfBitMap & 0x7;

    while (ulCount--)
    {
      ulSet += NTDLL_nibbleBitCount[*lpOut >> 4];
      ulSet += NTDLL_nibbleBitCount[*lpOut & 0xf];
      lpOut++;
    }

    if (ulRemainder)
    {
      bMasked = *lpOut & NTDLL_maskBits[ulRemainder];
      ulSet += NTDLL_nibbleBitCount[bMasked >> 4];
      ulSet += NTDLL_nibbleBitCount[bMasked & 0xf];
    }
  }
  return ulSet;
}

/*************************************************************************
 * RtlNumberOfClearBits	[NTDLL.@]
 *
 * Find the number of clear bits in a bitmap.
 *
 * PARAMS
 *  lpBits [I] Bitmap pointer
 *
 * RETURNS
 *  The number of clear bits.
 */
ULONG WINAPI RtlNumberOfClearBits(PCRTL_BITMAP lpBits)
{
  TRACE("(%p)\n", lpBits);

  if (lpBits)
    return lpBits->SizeOfBitMap - RtlNumberOfSetBits(lpBits);
  return 0;
}

/*************************************************************************
 * RtlFindMostSignificantBit	[NTDLL.@]
 *
 * Find the most significant bit in a 64 bit integer.
 *
 * RETURNS
 *  The position of the most significant bit.
 */
CCHAR WINAPI RtlFindMostSignificantBit(ULONGLONG ulLong)
{
    signed char ret = 32;
    DWORD dw;

    if (!(dw = (ulLong >> 32)))
    {
        ret = 0;
        dw = (DWORD)ulLong;
    }
    if (dw & 0xffff0000)
    {
        dw >>= 16;
        ret += 16;
    }
    if (dw & 0xff00)
    {
        dw >>= 8;
        ret += 8;
    }
    if (dw & 0xf0)
    {
        dw >>= 4;
        ret += 4;
    }
    return ret + NTDLL_mostSignificant[dw];
}

/*************************************************************************
 * RtlFindLeastSignificantBit	[NTDLL.@]
 *
 * Find the least significant bit in a 64 bit integer.
 *
 * RETURNS
 *  The position of the least significant bit.
 */
CCHAR WINAPI RtlFindLeastSignificantBit(ULONGLONG ulLong)
{
    signed char ret = 0;
    DWORD dw;

    if (!(dw = (DWORD)ulLong))
    {
        ret = 32;
        if (!(dw = ulLong >> 32)) return -1;
    }
    if (!(dw & 0xffff))
    {
        dw >>= 16;
        ret += 16;
    }
    if (!(dw & 0xff))
    {
        dw >>= 8;
        ret += 8;
    }
    if (!(dw & 0x0f))
    {
        dw >>= 4;
        ret += 4;
    }
    return ret + NTDLL_leastSignificant[dw & 0x0f];
}

/*************************************************************************
 * NTDLL_RunSortFn
 *
 * Internal helper: qsort comparison function for RTL_BITMAP_RUN arrays
 */
static int NTDLL_RunSortFn(const void *lhs, const void *rhs)
{
  if (((const RTL_BITMAP_RUN*)lhs)->NumberOfBits > ((const RTL_BITMAP_RUN*)rhs)->NumberOfBits)
    return -1;
  return 1;
}

/*************************************************************************
 * NTDLL_FindSetRun
 *
 * Internal helper: Find the next run of set bits in a bitmap.
 */
static ULONG NTDLL_FindSetRun(PCRTL_BITMAP lpBits, ULONG ulStart, PULONG lpSize)
{
  LPBYTE lpOut;
  ULONG ulFoundAt = 0, ulCount = 0;

  /* FIXME: It might be more efficient/cleaner to manipulate four bytes
   * at a time. But beware of the pointer arithmetics...
   */
  lpOut = ((BYTE*)lpBits->Buffer) + (ulStart >> 3u);

  while (1)
  {
    /* Check bits in first byte */
    const BYTE bMask = (0xff << (ulStart & 7)) & 0xff;
    const BYTE bFirst = *lpOut & bMask;

    if (bFirst)
    {
      /* Have a set bit in first byte */
      if (bFirst != bMask)
      {
        /* Not every bit is set */
        ULONG ulOffset;

        if (bFirst & 0x0f)
          ulOffset = NTDLL_leastSignificant[bFirst & 0x0f];
        else
          ulOffset = 4 + NTDLL_leastSignificant[bFirst >> 4];
        ulStart += ulOffset;
        ulFoundAt = ulStart;
        for (;ulOffset < 8; ulOffset++)
        {
          if (!(bFirst & (1 << ulOffset)))
          {
            *lpSize = ulCount;
            return ulFoundAt; /* Set from start, but not until the end */
          }
          ulCount++;
          ulStart++;
        }
        /* Set to the end - go on to count further bits */
        lpOut++;
        break;
      }
      /* every bit from start until the end of the byte is set */
      ulFoundAt = ulStart;
      ulCount = 8 - (ulStart & 7);
      ulStart = (ulStart & ~7u) + 8;
      lpOut++;
      break;
    }
    ulStart = (ulStart & ~7u) + 8;
    lpOut++;
    if (ulStart >= lpBits->SizeOfBitMap)
      return ~0U;
  }

  /* Check if reached the end of bitmap */
  if (ulStart >= lpBits->SizeOfBitMap) {
    *lpSize = ulCount - (ulStart - lpBits->SizeOfBitMap);
    return ulFoundAt;
  }

  /* Count blocks of 8 set bits */
  while (*lpOut == 0xff)
  {
    ulCount += 8;
    ulStart += 8;
    if (ulStart >= lpBits->SizeOfBitMap)
    {
      *lpSize = ulCount - (ulStart - lpBits->SizeOfBitMap);
      return ulFoundAt;
    }
    lpOut++;
  }

  /* Count remaining contiguous bits, if any */
  if (*lpOut & 1)
  {
    ULONG ulOffset = 0;

    for (;ulOffset < 7u; ulOffset++)
    {
      if (!(*lpOut & (1 << ulOffset)))
        break;
      ulCount++;
    }
  }
  *lpSize = ulCount;
  return ulFoundAt;
}

/*************************************************************************
 * NTDLL_FindClearRun
 *
 * Internal helper: Find the next run of set bits in a bitmap.
 */
static ULONG NTDLL_FindClearRun(PCRTL_BITMAP lpBits, ULONG ulStart, PULONG lpSize)
{
  LPBYTE lpOut;
  ULONG ulFoundAt = 0, ulCount = 0;

  /* FIXME: It might be more efficient/cleaner to manipulate four bytes
   * at a time. But beware of the pointer arithmetics...
   */
  lpOut = ((BYTE*)lpBits->Buffer) + (ulStart >> 3u);

  while (1)
  {
    /* Check bits in first byte */
    const BYTE bMask = (0xff << (ulStart & 7)) & 0xff;
    const BYTE bFirst = (~*lpOut) & bMask;

    if (bFirst)
    {
      /* Have a clear bit in first byte */
      if (bFirst != bMask)
      {
        /* Not every bit is clear */
        ULONG ulOffset;

        if (bFirst & 0x0f)
          ulOffset = NTDLL_leastSignificant[bFirst & 0x0f];
        else
          ulOffset = 4 + NTDLL_leastSignificant[bFirst >> 4];
        ulStart += ulOffset;
        ulFoundAt = ulStart;
        for (;ulOffset < 8; ulOffset++)
        {
          if (!(bFirst & (1 << ulOffset)))
          {
            *lpSize = ulCount;
            return ulFoundAt; /* Clear from start, but not until the end */
          }
          ulCount++;
          ulStart++;
        }
        /* Clear to the end - go on to count further bits */
        lpOut++;
        break;
      }
      /* Every bit from start until the end of the byte is clear */
      ulFoundAt = ulStart;
      ulCount = 8 - (ulStart & 7);
      ulStart = (ulStart & ~7u) + 8;
      lpOut++;
      break;
    }
    ulStart = (ulStart & ~7u) + 8;
    lpOut++;
    if (ulStart >= lpBits->SizeOfBitMap)
      return ~0U;
  }

  /* Check if reached the end of bitmap */
  if (ulStart >= lpBits->SizeOfBitMap) {
    *lpSize = ulCount - (ulStart - lpBits->SizeOfBitMap);
    return ulFoundAt;
  }

  /* Count blocks of 8 clear bits */
  while (!*lpOut)
  {
    ulCount += 8;
    ulStart += 8;
    if (ulStart >= lpBits->SizeOfBitMap)
    {
      *lpSize = ulCount - (ulStart - lpBits->SizeOfBitMap);
      return ulFoundAt;
    }
    lpOut++;
  }

  /* Count remaining contiguous bits, if any */
  if (!(*lpOut & 1))
  {
    ULONG ulOffset = 0;

    for (;ulOffset < 7u; ulOffset++)
    {
      if (*lpOut & (1 << ulOffset))
        break;
      ulCount++;
    }
  }
  *lpSize = ulCount;
  return ulFoundAt;
}

/*************************************************************************
 * RtlFindNextForwardRunSet	[NTDLL.@]
 *
 * Find the next run of set bits in a bitmap.
 *
 * PARAMS
 *  lpBits  [I] Bitmap pointer
 *  ulStart [I] Bit position to start searching from
 *  lpPos   [O] Start of run
 *
 * RETURNS
 *  Success: The length of the next set run in the bitmap. lpPos is set to
 *           the start of the run.
 *  Failure: 0, if no run is found or any parameters are invalid.
 */
ULONG WINAPI RtlFindNextForwardRunSet(PCRTL_BITMAP lpBits, ULONG ulStart, PULONG lpPos)
{
  ULONG ulSize = 0;

  TRACE("(%p,%u,%p)\n", lpBits, ulStart, lpPos);

  if (lpBits && ulStart < lpBits->SizeOfBitMap && lpPos)
    *lpPos = NTDLL_FindSetRun(lpBits, ulStart, &ulSize);

  return ulSize;
}

/*************************************************************************
 * RtlFindNextForwardRunClear	[NTDLL.@]
 *
 * Find the next run of clear bits in a bitmap.
 *
 * PARAMS
 *  lpBits  [I] Bitmap pointer
 *  ulStart [I] Bit position to start searching from
 *  lpPos   [O] Start of run
 *
 * RETURNS
 *  Success: The length of the next clear run in the bitmap. lpPos is set to
 *           the start of the run.
 *  Failure: 0, if no run is found or any parameters are invalid.
 */
ULONG WINAPI RtlFindNextForwardRunClear(PCRTL_BITMAP lpBits, ULONG ulStart, PULONG lpPos)
{
  ULONG ulSize = 0;

  TRACE("(%p,%u,%p)\n", lpBits, ulStart, lpPos);

  if (lpBits && ulStart < lpBits->SizeOfBitMap && lpPos)
    *lpPos = NTDLL_FindClearRun(lpBits, ulStart, &ulSize);

  return ulSize;
}

/*************************************************************************
 * RtlFindLastBackwardRunSet	[NTDLL.@]
 *
 * Find a previous run of set bits in a bitmap.
 *
 * PARAMS
 *  lpBits  [I] Bitmap pointer
 *  ulStart [I] Bit position to start searching from
 *  lpPos   [O] Start of run
 *
 * RETURNS
 *  Success: The length of the previous set run in the bitmap. lpPos is set to
 *           the start of the run.
 *  Failure: 0, if no run is found or any parameters are invalid.
 */
ULONG WINAPI RtlFindLastBackwardRunSet(PCRTL_BITMAP lpBits, ULONG ulStart, PULONG lpPos)
{
  FIXME("(%p,%u,%p)-stub!\n", lpBits, ulStart, lpPos);
  return 0;
}

/*************************************************************************
 * RtlFindLastBackwardRunClear	[NTDLL.@]
 *
 * Find a previous run of clear bits in a bitmap.
 *
 * PARAMS
 *  lpBits  [I] Bitmap pointer
 *  ulStart [I] Bit position to start searching from
 *  lpPos   [O] Start of run
 *
 * RETURNS
 *  Success: The length of the previous clear run in the bitmap. lpPos is set
 *           to the start of the run.
 *  Failure: 0, if no run is found or any parameters are invalid.
 */
ULONG WINAPI RtlFindLastBackwardRunClear(PCRTL_BITMAP lpBits, ULONG ulStart, PULONG lpPos)
{
  FIXME("(%p,%u,%p)-stub!\n", lpBits, ulStart, lpPos);
  return 0;
}

/*************************************************************************
 * NTDLL_FindRuns
 *
 * Internal implementation of RtlFindSetRuns/RtlFindClearRuns.
 */
static ULONG NTDLL_FindRuns(PCRTL_BITMAP lpBits, PRTL_BITMAP_RUN lpSeries,
                            ULONG ulCount, BOOLEAN bLongest,
                            ULONG (*fn)(PCRTL_BITMAP,ULONG,PULONG))
{
  BOOL bNeedSort = ulCount > 1;
  ULONG ulPos = 0, ulRuns = 0;

  TRACE("(%p,%p,%d,%d)\n", lpBits, lpSeries, ulCount, bLongest);

  if (!ulCount)
    return ~0U;

  while (ulPos < lpBits->SizeOfBitMap)
  {
    /* Find next set/clear run */
    ULONG ulSize, ulNextPos = fn(lpBits, ulPos, &ulSize);

    if (ulNextPos == ~0U)
      break;

    if (bLongest && ulRuns == ulCount)
    {
      /* Sort runs with shortest at end, if they are out of order */
      if (bNeedSort)
        qsort(lpSeries, ulRuns, sizeof(RTL_BITMAP_RUN), NTDLL_RunSortFn);

      /* Replace last run if this one is bigger */
      if (ulSize > lpSeries[ulRuns - 1].NumberOfBits)
      {
        lpSeries[ulRuns - 1].StartingIndex = ulNextPos;
        lpSeries[ulRuns - 1].NumberOfBits = ulSize;

        /* We need to re-sort the array, _if_ we didn't leave it sorted */
        if (ulRuns > 1 && ulSize > lpSeries[ulRuns - 2].NumberOfBits)
          bNeedSort = TRUE;
      }
    }
    else
    {
      /* Append to found runs */
      lpSeries[ulRuns].StartingIndex = ulNextPos;
      lpSeries[ulRuns].NumberOfBits = ulSize;
      ulRuns++;

      if (!bLongest && ulRuns == ulCount)
        break;
    }
    ulPos = ulNextPos + ulSize;
  }
  return ulRuns;
}

/*************************************************************************
 * RtlFindSetRuns	[NTDLL.@]
 *
 * Find a series of set runs in a bitmap.
 *
 * PARAMS
 *  lpBits   [I] Bitmap pointer
 *  lpSeries [O] Array for each run found
 *  ulCount  [I] Number of runs to find
 *  bLongest [I] Whether to find the very longest runs or not
 *
 * RETURNS
 *  The number of set runs found.
 */
ULONG WINAPI RtlFindSetRuns(PCRTL_BITMAP lpBits, PRTL_BITMAP_RUN lpSeries,
                            ULONG ulCount, BOOLEAN bLongest)
{
  TRACE("(%p,%p,%u,%d)\n", lpBits, lpSeries, ulCount, bLongest);

  return NTDLL_FindRuns(lpBits, lpSeries, ulCount, bLongest, NTDLL_FindSetRun);
}

/*************************************************************************
 * RtlFindClearRuns	[NTDLL.@]
 *
 * Find a series of clear runs in a bitmap.
 *
 * PARAMS
 *  lpBits   [I] Bitmap pointer
 *  ulSeries [O] Array for each run found
 *  ulCount  [I] Number of runs to find
 *  bLongest [I] Whether to find the very longest runs or not
 *
 * RETURNS
 *  The number of clear runs found.
 */
ULONG WINAPI RtlFindClearRuns(PCRTL_BITMAP lpBits, PRTL_BITMAP_RUN lpSeries,
                              ULONG ulCount, BOOLEAN bLongest)
{
  TRACE("(%p,%p,%u,%d)\n", lpBits, lpSeries, ulCount, bLongest);

  return NTDLL_FindRuns(lpBits, lpSeries, ulCount, bLongest, NTDLL_FindClearRun);
}

/*************************************************************************
 * RtlFindLongestRunSet	[NTDLL.@]
 *
 * Find the longest set run in a bitmap.
 *
 * PARAMS
 *  lpBits   [I] Bitmap pointer
 *  pulStart [O] Destination for start of run
 *
 * RETURNS
 *  The length of the run found, or 0 if no run is found.
 */
ULONG WINAPI RtlFindLongestRunSet(PCRTL_BITMAP lpBits, PULONG pulStart)
{
  RTL_BITMAP_RUN br;

  TRACE("(%p,%p)\n", lpBits, pulStart);

  if (RtlFindSetRuns(lpBits, &br, 1, TRUE) == 1)
  {
    if (pulStart)
      *pulStart = br.StartingIndex;
    return br.NumberOfBits;
  }
  return 0;
}

/*************************************************************************
 * RtlFindLongestRunClear	[NTDLL.@]
 *
 * Find the longest clear run in a bitmap.
 *
 * PARAMS
 *  lpBits   [I] Bitmap pointer
 *  pulStart [O] Destination for start of run
 *
 * RETURNS
 *  The length of the run found, or 0 if no run is found.
 */
ULONG WINAPI RtlFindLongestRunClear(PCRTL_BITMAP lpBits, PULONG pulStart)
{
  RTL_BITMAP_RUN br;

  TRACE("(%p,%p)\n", lpBits, pulStart);

  if (RtlFindClearRuns(lpBits, &br, 1, TRUE) == 1)
  {
    if (pulStart)
      *pulStart = br.StartingIndex;
    return br.NumberOfBits;
  }
  return 0;
}

DECLARE_CRT_EXPORT("RtlFindClearBitsAndSet", RtlFindClearBitsAndSet);
DECLARE_CRT_EXPORT("RtlClearBits", RtlClearBits);
DECLARE_CRT_EXPORT("RtlAreBitsSet", RtlAreBitsSet);
