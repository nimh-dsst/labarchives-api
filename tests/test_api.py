from labarchives_api.client import generate_signature

# Values from the LabArchives API documentation
test_akid: str = "0234wedkfjrtfd34er"
test_api_method: str = "entry_attachment"
test_expires: int = 264433207000
test_access_password: str = "1234567890"
test_signature: str = (
    "mT7pS%2BKgqlNseR0bo4YLQOVIsgOugMWzlQGllInXS25Q7V"
    + "pA6lRmL0nUq%2FUUdrlF%2BWV7POYE1vcwvN%2Fpnac7bw%3D%3D"
)


def test_generate_signature():
    assert (
        generate_signature(
            test_akid, test_api_method, test_expires, test_access_password
        )
        == test_signature
    )
