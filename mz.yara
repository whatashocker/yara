rule mz
{
	meta:
		description="Is the file a MZ"
	strings:
		$mz_magic = {4D 5A}
	condition:
		all of them
}
