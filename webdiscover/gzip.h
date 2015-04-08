#pragma once

#include <zlib.h>

int gzcompress(Bytef *data, uLong ndata,
               Bytef *zdata, uLong *nzdata);

int gzdecompress(Byte *zdata, uLong nzdata,
                 Byte *data, uLong *ndata);

int inflate_read(char *source, int len, char **dest, int gzip);