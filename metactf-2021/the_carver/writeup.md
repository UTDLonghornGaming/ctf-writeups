# MetaCTF 2021 - The Carver - Writeup

This problem could have been solved with a lot of time and effort, but screw that. 

## Analysis

We are provided with a dump file, which I presume contains information of some sort. Too much information, for that matter.

## Forensic Analysis

Since we know from the description that our flag is in standard `MetaCTF{}` format, I converted the string `MetaCT` to Base64, resulting in `TWV0YUNU`.
I searched the dump file for this string. No results. 

However, scrolling through the dump file, we see strings such as `C o o r d i n a t e d   U n i v e r s a l   T i m e`, which contains spaces between every letter.
This inspired me to search the dump file for the string `T W V 0 Y U N U`, and we get a couple hits!

Looking for the longest base64 string with the given prefix, we find the string `T W V 0 Y U N U R n t z b 2 1 l X 3 B l b 3 B s Z V 9 j Y X J 2 Z V 9 w d W 1 w a 2 l u c 1 9 p X 2 N h c n Z l X 2 1 l b W 9 y e X 0 = `, which is clearly the full string due to the equals sign at the end.

## Conclusion

Decoding the string, we get the flag:

```
MetaCTF{some_people_carve_pumpkins_i_carve_memory}
```

A simple 2 minute challenge, very nice!
