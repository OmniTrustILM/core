"""Fixed replacement helper used only by the public asset regression tests."""
def replace_once(source,before,after):
    assert source.count(before)==1,'fixed body substitution count'
    return source.replace(before,after)
