# COFFLoader2

This repo contains the source code of a Common Object File Format (COFF) loader, which is a rewrite of the research and implementation done by Kevin Haubris [@Kev169](https://twitter.com/kev169) on the [TrustedSec](https://www.trustedsec.com) GitHub repo [here](https://github.com/trustedsec/COFFLoader). Kevin also wrote an article about [building your own COFF loader](https://www.trustedsec.com/blog/coffloader-building-your-own-in-memory-loader-or-how-to-run-bofs/)

Kevin did an excellent job in figuring out the relocations and implementing the beacon compatibility layer. This repo takes it a bit further in making the code prettier (beauty is in the eyes of the beholder anyway) and more readable. This repo includes more comments, extracted COFF-related code into re-usable functions, usage of MSVC-compliant functions, and fix issues with MSVC-compiled BOFs. Also, while the code is initially inspired by Kevin's work, the approach to the implementation of the relocations and memory allocation is different.

### Why?

Rewriting code is an excellent way to improve one's understanding of a topic. This was the main drive for rewriting the code. Another reason is that the original code is *probably* not meant for the VS toolchain, which is apparent in the fact that MSVC won't compile the code because of its insecure-function warnings and that the loader won't load MSVC-compiled BOFs. Since I like developing and compiling my BOFs with VS, this was another good reason to rewrite. Further, the original code seemed too complicated to my simple brain. For example, when I was trying to understand the original code, I found myself reading an `if statement` which is inside an `else if` that is inside another `else` which is inside a `for` loop that is inside another `for` loop. My brain couldn't keep up, the folks at TrustedSec are too smart for me haha. The code also lacked variables which made it quite challenging to read, so a rewrite seemed definitely worth the time and effort. Looking retrospectively, I am pretty happy about the decision!

### What?

The rewrite is focussed on the COFF-loading process only. I did not modify the beacon compatibility layer. A non-comprehensive list of changes

- Re-implemented the relocations. The code now performs relocations on the .text section only, which is sufficient to get the COFF executed. However, applying the relocations to any other section should be straightforward with the new structure
- Improved readability by removing some nesting, using variables, and extracting some re-usable code into functions
- Used WIN32 API calls to open and read the file instead of the standard library functions
- Avoid double allocation for every section. The exception is .text section which is allocated again on PAGE_EXECUTE_READWRITE memory region. The other sections are located in PAGE_READONLY memory region.
- Removed fixed-size allocation for function mapping and check of whether the mapping is within 4GB limit by ensuring that the mapping will be right after the .text section.
- Added more error checking here and there

### Todo

While I didn't have any issues with testing, I'll maintain the original disclaimer. This code should be used for testing purposes, it needs further testing before using in production.

What I'd like to do from here is using the loader over the network and take a deeper look into the beacon compatibility layer to see how this can be transformed into a COFF-based C2 and perhaps add x86 support. Much more can be added/modified but at one point I realized that the cycle of refactoring can continue forever and wanted to share a first version. Hopefully a blog post and more comments will follow.

### Credits

1. Huge thanks to Kevin [@Kev169](https://twitter.com/kev169) and the TrustedSec team for sharing their code. Going through the code and rewriting it made me realize the great effort and time invested in the original implementation. Great job Kevin and TrustedSec!
2. Patryk Czeczko ([@0xpat](https://twitter.com/0xPat)) wrote a nice blog article about COFF loaders [on his blog](https://0xpat.github.io/Malware_development_part_8/), was quite useful
3. While not directly related to the re-implementation, I liked the [BOF2Shellcode](https://medium.com/falconforce/bof2shellcode-a-tutorial-converting-a-stand-alone-bof-loader-into-shellcode-6369aa518548) article by Gijs Hollestelle ([@gijs_h](https://twitter.com/gijs_h)) and found it to be an exciting read.
