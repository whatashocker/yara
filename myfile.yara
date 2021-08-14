rule myapp
{
	meta:
		description="my exe find"
	strings:
		$a = "WindowsFormsAppTest.pdb"
	condition:
		all of them
}
