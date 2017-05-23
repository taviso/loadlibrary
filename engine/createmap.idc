#include <idc.idc>

static main()
{
    auto file;

    // Wait for auto-analysis to complete...
    Wait();

    file = fopen(ARGV[1], "w");

    // Produce MAP file.
    GenerateFile(OFILE_MAP, file, 0, ~0, GENFLG_MAPSEGS | GENFLG_MAPDMNG);

    // Finished.
    fclose(file);
    Exit(0);
}
