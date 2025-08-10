dirname = 
commonflags = -Fe$(dirname)\ -Fo$(dirname)\ -MD -FS
clflags = -Zi -fsanitize=address
dotnetflags = --nologo -o psmod_build

all: cli dll psmod

release: clflags = -O2 -GL -Ob3 -DNDEBUG
release: dotnetflags += -c Release
release: all

cli: dirname = cli
cli: envpath_cli.c envpath.c envpath.h
	if not exist $(dirname) mkdir $(dirname) && \
		cl $(clflags) $(commonflags) envpath.c envpath_cli.c

dll: dirname = dll
dll: envpath.c envpath.h
	if not exist $(dirname) mkdir $(dirname) && \
		cl $(clflags) $(commonflags) -LD -DDLL_BUILD envpath.c

psmod_build: Main.cs
	dotnet build $(dotnetflags)

psmod: psmod_build BinEnvPath.psd1 dll
	if not exist psmod mkdir psmod && \
		copy BinEnvPath.psd1 psmod && \
		copy psmod_build\envpath_msil.dll psmod &&\
		copy dll\envpath.dll psmod

clean:
	del vc140.pdb & rd /s /q obj psmod psmod_build dll cli & cd .
