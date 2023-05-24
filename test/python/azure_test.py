import duckdb

def test_azure():
    conn = duckdb.connect('');
    conn.execute("SELECT azure('Sam') as value;");
    res = conn.fetchall()
    assert(res[0][0] == "Azure Sam 🐥");