// mpqfind - answer "which archive in this chain actually holds this file?"
//
// mpqcat guesses precedence by sorting the full archive PATH (longest first,
// then reverse lexical).  That is wrong twice over: every ..\enUS\ path is
// longer than every main-directory one, so the locale archives always win, and
// patch-CZZ beats patch-B on length alone.  The result is that mpqcat happily
// returns the stock 3.3.5 copy of a file Ascension overrides.
//
//   mpqfind <DataDir> --which <InternalPath>
//       print every archive that contains the path, with the size it holds,
//       so the real override chain can be established by inspection.
//
//   mpqfind <DataDir> --from <ArchiveName> <InternalPath> [OutFile]
//       read the path out of ONE named archive (basename, e.g. patch-B.MPQ),
//       bypassing precedence entirely.
//
// Read-only: archives are opened MPQ_OPEN_READ_ONLY and never written.
#include <windows.h>
#include <stdio.h>
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
    std::sort(out.begin(), out.end());
    return out;
}

static std::string Base(const std::string& p)
{
    size_t s = p.find_last_of("\\/");
    return s == std::string::npos ? p : p.substr(s + 1);
}

static bool ReadOne(const std::string& arc, const std::string& name,
                    std::vector<char>& buf)
{
    HANDLE h = NULL;
    if (!SFileOpenArchive(arc.c_str(), 0, MPQ_OPEN_READ_ONLY, &h)) return false;
    HANDLE f = NULL;
    bool ok = false;
    if (SFileOpenFileEx(h, name.c_str(), SFILE_OPEN_FROM_MPQ, &f))
    {
        DWORD hi = 0;
        DWORD size = SFileGetFileSize(f, &hi);
        buf.assign(size ? size : 1, 0);
        DWORD got = 0;
        if (SFileReadFile(f, buf.data(), size, &got, NULL) || got)
        {
            buf.resize(got);
            ok = true;
        }
        SFileCloseFile(f);
    }
    SFileCloseArchive(h);
    return ok;
}

int main(int argc, char** argv)
{
    if (argc < 4)
    {
        fprintf(stderr,
                "usage: mpqfind <DataDir> --which <InternalPath>\n"
                "       mpqfind <DataDir> --from <Archive.MPQ> <InternalPath> [Out]\n");
        return 2;
    }
    std::string data = argv[1], mode = argv[2];
    std::vector<std::string> archives = FindArchives(data);

    if (mode == "--which")
    {
        std::string name = argv[3];
        int hits = 0;
        for (const std::string& arc : archives)
        {
            std::vector<char> buf;
            if (!ReadOne(arc, name, buf)) continue;
            ++hits;
            printf("%10zu  %s\n", buf.size(), Base(arc).c_str());
        }
        if (!hits) { printf("(not found in %zu archive(s))\n", archives.size()); return 1; }
        return 0;
    }

    if (mode == "--chain")
    {
        // mpqfind <DataDir> --chain <a.MPQ,b.MPQ,...> <InternalPath> [OutFile]
        // Walk the given archives in order and take the first hit.  This is the
        // only trustworthy way to read Interface files out of this client: the
        // Ascension UI lives entirely in patch-B.MPQ and must be consulted
        // before the stock enUS chain, which any path- or name-based sort gets
        // backwards.
        if (argc < 5) { fprintf(stderr, "--chain needs <list> <InternalPath>\n"); return 2; }
        std::string list = argv[3], name = argv[4];
        std::string out = argc > 5 ? argv[5] : "";
        std::vector<std::string> order;
        for (size_t i = 0, j; i <= list.size(); i = j + 1)
        {
            j = list.find(',', i);
            if (j == std::string::npos) j = list.size();
            std::string w = list.substr(i, j - i);
            if (!w.empty()) order.push_back(w);
        }
        for (const std::string& want : order)
        {
            for (const std::string& arc : archives)
            {
                if (_stricmp(Base(arc).c_str(), want.c_str()) != 0) continue;
                std::vector<char> buf;
                if (!ReadOne(arc, name, buf)) break;
                if (out.empty()) { fwrite(buf.data(), 1, buf.size(), stdout); return 0; }
                FILE* o = fopen(out.c_str(), "wb");
                if (!o) { fprintf(stderr, "cannot write %s\n", out.c_str()); return 1; }
                fwrite(buf.data(), 1, buf.size(), o);
                fclose(o);
                fprintf(stderr, "%zu bytes from %s\n", buf.size(), want.c_str());
                return 0;
            }
        }
        return 1;
    }

    if (mode == "--from")
    {
        if (argc < 5) { fprintf(stderr, "--from needs <Archive.MPQ> <InternalPath>\n"); return 2; }
        std::string want = argv[3], name = argv[4];
        std::string out = argc > 5 ? argv[5] : "";
        for (const std::string& arc : archives)
        {
            if (_stricmp(Base(arc).c_str(), want.c_str()) != 0) continue;
            std::vector<char> buf;
            if (!ReadOne(arc, name, buf)) { fprintf(stderr, "not in %s\n", want.c_str()); return 1; }
            if (out.empty()) { fwrite(buf.data(), 1, buf.size(), stdout); return 0; }
            FILE* o = fopen(out.c_str(), "wb");
            if (!o) { fprintf(stderr, "cannot write %s\n", out.c_str()); return 1; }
            fwrite(buf.data(), 1, buf.size(), o);
            fclose(o);
            fprintf(stderr, "%zu bytes -> %s\n", buf.size(), out.c_str());
            return 0;
        }
        fprintf(stderr, "no archive named %s under %s\n", want.c_str(), data.c_str());
        return 1;
    }

    fprintf(stderr, "unknown mode %s\n", mode.c_str());
    return 2;
}
