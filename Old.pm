package Data::Password::Entropy::Old;
use strict;
use warnings;
use Exporter;
our @ISA = qw/Exporter/;
our @EXPORT = qw/pwstrengthcheck/;
our $VERSION = '0.2';

sub pwstrengthcheck($){
	my $pw = shift;

	my $pwlength = length($pw);
	if($pwlength>5){
		$pwlength = 5;
	}

	my $numnumeric = $pw;
	$numnumeric =~ s/[^0-9]//g;
	my $numeric = ($pwlength - length($numnumeric));
	if($numeric>3){
		$numeric = 3;
	}

	my $symbols = $pw;
	$symbols =~ s/[^\W]//g;
	my $numsymbols = ($pwlength - length($symbols));
	if($numsymbols>3){
		$numsymbols = 3;
	}

	my $numupper = $pw;
	$numupper =~ s/[^A-Z]//g;
	my $upper = ($pwlength - length($numupper));
	if($upper>3){
		$upper = 3;
	}
	my $pwstrength = (($pwlength*10)-20) + ($numeric*10) + ($numsymbols*15) + ($upper*10);

	if($pwstrength < 0){
		$pwstrength = 0;
	}

	if($pwstrength > 100){
		$pwstrength = 100;
	}

	return $pwstrength;
}

=pod

=head1 NAME

Data::Password::Entropy::Old - Calculate the password strength

=head1 SYNOPSIS

	use Data::Password::Entropy::Old;
	my $password = "Dis";
	my $pwtest = pwstrengthcheck($password);
	print "Strength $pwtest\n";#between 0 and 100

	#Based on http://mxr.mozilla.org/seamonkey/source/security/manager/pki/resources/content/password.js

=head1 DESCRIPTION

Data::Password::Entropy::Old - Calculate the password strength

=head1 AUTHOR

    -

=head1 COPYRIGHT

	This program is free software; you can redistribute
	it and/or modify it under the same terms as Perl itself.

=head1 SEE ALSO



=cut
