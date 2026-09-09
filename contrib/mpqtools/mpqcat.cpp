// mpqcat - extract a file from an MPQ chain BY NAME, with no (listfile) needed.
//
// Ascension's custom patch archives ship without a listfile, so mpqls/mpqdump
// (which enumerate) report nothing for them.  SFileOpenFileEx resolves a name
// through the hash table directly, so an exact internal path still works.
//
//   mpqcat <DataDir> <InternalPath> [OutFile]      extract one file
//   mpqcat <DataDir> --list <PathListFile> <OutDir> extract every path that exists
//
// Archives are tried newest-first (reverse lexical), which matches WoW's
// patch-<letter> precedence closely enough for read-only archaeology.
#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>
#include <algorithm>
#include "StormLib.h"

static std::vector<std::string> FindArchives(const std::string& data)
{
    std::vector<std::string> out;
    const char* subs[] = { "", "\\enUS" };
    for (const char* sub : subs)
    {
        std::string dir = data + sub;
        std::string pat = dir + "\\*.MPQ";
        WIN32_FIND_DATAA fd;
        HANDLE h = FindFirstFileA(pat.c_str(), &fd);
        if (h == INVALID_HANDLE_VALUE) continue;
        do {
            if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
                out.push_back(dir + "\\" + fd.cFileName);
        } while (FindNextFileA(h, &fd));
        FindClose(h);
    }
    // longest name first, then reverse lexical: patch-CV beats patch-C beats patch-3
    std::sort(out.begin(), out.end(), [](const std::string& a, const std::string& b) {
        if (a.size() != b.size()) return a.size() > b.size();
        return a > b;
    });
    return out;
}

static bool ExtractOne(const std::vector<std::string>& archives,
                       const std::string& name, const std::string& outPath,
                       bool quiet)
{
    for (const std::string& arc : archives)
    {
        HANDLE h = NULL;
        if (!SFileOpenArchive(arc.c_str(), 0, MPQ_OPEN_READ_ONLY, &h)) continue;
        HANDLE f = NULL;
        if (SFileOpenFileEx(h, name.c_str(), SFILE_OPEN_FROM_MPQ, &f))
        {
            DWORD hi = 0;
            DWORD size = SFileGetFileSize(f, &hi);
            std::vector<char> buf(size ? size : 1);
            DWORD got = 0;
            SFileReadFile(f, buf.data(), size, &got, NULL);
            SFileCloseFile(f);
            SFileCloseArchive(h);
            if (!outPath.empty())
            {
                FILE* o = fopen(outPath.c_str(), "wb");
                if (!o) { fprintf(stderr, "cannot write %s\n", outPath.c_str()); return false; }
                fwrite(buf.data(), 1, got, o);
                fclose(o);
            }
            else
            {
                fwrite(buf.data(), 1, got, stdout);
            }
            if (!quiet)
                fprintf(stderr, "%s  <- %s  (%lu bytes)\n",
                        name.c_str(), arc.c_str(), (unsigned long)got);
            else
                printf("OK %lu %s %s\n", (unsigned long)got, arc.c_str(), name.c_str());
            return true;
        }
        SFileCloseArchive(h);
    }
    if (quiet) printf("-- %s\n", name.c_str());
    else fprintf(stderr, "NOT FOUND: %s\n", name.c_str());
    return false;
}

static std::string SafeName(std::string s)
{
    for (char& c : s) if (c == '\\' || c == '/' || c == ':') c = '_';
    return s;
}

int main(int argc, char** argv)
{
    if (argc < 3)
    {
        printf("usage: mpqcat <DataDir> <InternalPath> [OutFile]\n"
               "       mpqcat <DataDir> --list <PathListFile> <OutDir>\n");
        return 2;
    }
    std::string data = argv[1];
    for (char& c : data) if (c == '/') c = '\\';
    while (!data.empty() && data.back() == '\\') data.pop_back();

    std::vector<std::string> archives = FindArchives(data);
    fprintf(stderr, "%zu archive(s) under %s\n", archives.size(), data.c_str());

    if (std::string(argv[2]) == "--list")
    {
        if (argc < 5) { printf("need <PathListFile> <OutDir>\n"); return 2; }
        FILE* lf = fopen(argv[3], "rb");
        if (!lf) { printf("cannot read %s\n", argv[3]); return 2; }
        CreateDirectoryA(argv[4], NULL);
        char line[1024];
        int found = 0, total = 0;
        while (fgets(line, sizeof(line), lf))
        {
            std::string s(line);
            while (!s.empty() && (s.back() == '\n' || s.back() == '\r' || s.back() == ' ')) s.pop_back();
            if (s.empty() || s[0] == '#') continue;
            for (char& c : s) if (c == '/') c = '\\';
            ++total;
            std::string out = std::string(argv[4]) + "\\" + SafeName(s);
            if (ExtractOne(archives, s, out, true)) ++found;
        }
        fclose(lf);
        fprintf(stderr, "%d/%d found\n", found, total);
        return found ? 0 : 1;
    }

    std::string name = argv[2];
    for (char& c : name) if (c == '/') c = '\\';
    std::string out = (argc > 3) ? argv[3] : "";
    return ExtractOne(archives, name, out, false) ? 0 : 1;
}
