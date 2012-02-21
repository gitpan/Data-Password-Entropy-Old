use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile(
    'NAME'		=> 'Data::Password::Entropy::Old',
    'VERSION_FROM'	=> 'Old.pm', # finds $VERSION
    'PREREQ_PM'		=> {},
    ($] >= 5.005 ? (
      ABSTRACT_FROM => 'Old.pm', 
      AUTHOR     => 'Stefan Gipper <stefanos@cpan.org>',
    ) : ()),
);
