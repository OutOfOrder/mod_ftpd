#!/usr/bin/perl

use strict;

opendir(MYDIR, ".") or die "Unable to open directory";
print "Building TODO file for source directory\n";

open ( TODOFILE, "TODO_HEADER");
my $todo_header = do { local $/; <TODOFILE> };
close (TODOFILE);
open (TODOFILE, "> TODO");
print TODOFILE $todo_header;
while (my $entry = readdir(MYDIR)) {
	next if (!($entry =~ /\.[ch]$/));
	print "Parsing $entry.\n";
	open(DAFILE, $entry) or die "Unable to open file";
	my $linenumber = 0;
	while (my $line = <DAFILE>) {
		$linenumber ++;
		next if (!($line =~ /\/\* TODO: (.*)\*\//));
		print TODOFILE $entry.":".$linenumber.": ".$1."\n";
	}
	close(DAFILE);
}

closedir(MYDIR);
