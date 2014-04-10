use strict;
use warnings;
use ExtUtils::MakeMaker 6.3002;
our %BuildOptions;
require "BuildOptions.pm";
WriteMakefile(%BuildOptions);
