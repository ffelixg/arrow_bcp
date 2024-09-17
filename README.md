# arrow-bcp

    pip install arrow-bcp

When loading data into SQL Server from Python, the common methods are based on the ODBC interface and driver. While this is a tried and tested approach, the performance is not optimal. Reasons for this include:

* *minimal logging* cannot be used by regular insert statements unless they use table-valued parameters, which are cumbersome to use.
* General overhead caused by the ODBC specification. Most databases other than SQL Server provide their own connector in addition to an ODBC driver for this reason

Microsoft's Bulk Copy Program (bcp) command-line utility seems to use additional techniques beyond the ODBC specification and achieves better performance.

The purpose of this library is to (de-)serialize `pyarrow` dataframes into SQL Server's native format so that it can be understood and ingested by bcp, or equivalently, SQL Server's `BULK INSERT` statement.

Some wrappers around the bcp CLI are provided as well to simplify interaction with it.

For example usage including a benchmark for inserts, see the notebooks in the examples directory.

# Prerequisites

* An ODBC Driver Manager. On Linux/Mac, you may need to install unixODBC. On Windows, a driver manager is preinstalled.
* The ODBC Driver for SQL Server, which also bundles the bcp executable ([Link](https://learn.microsoft.com/en-us/sql/connect/odbc/download-odbc-driver-for-sql-server)).
* If the ODBC Driver for SQL Server was not installed using Microsoft's install script (e.g., by copy-pasting the binaries onto a system), you may need to configure `odbc.ini` (located in /etc/ on Linux) such that "ODBC Driver 17 for SQL Server," or whichever version you installed, points to the ODBC driver executable. If bcp is not on the PATH, you will also need to specify its location using `arrow_bcp.set_bcp_executable(path)`.

# Type mapping

## Arrow to SQL Server

| Arrow                    | SQL Server               |
| ------------------------ | ------------------------ |
| utf8                     | varchar(max) (utf8)      |
| binary                   | varbinary(max)           |
| fixedbinary              | varbinary(max)           |
| decimal128(p, s)         | decimal(p, s)            |
| boolean                  | bit                      |
| int8                     | smallint                 |
| uint8                    | tinyint                  |
| int16                    | smallint                 |
| uint16                   | int                      |
| int32                    | int                      |
| uint32                   | bigint                   |
| int64                    | bigint                   |
| uint64                   | decimal(20, 0)           |
| float16                  | real                     |
| float32                  | real                     |
| float64                  | float                    |
| date32                   | date                     |
| date64                   | datetime2                |
| timestamp(s/ms/us/ns)    | datetime2                |
| time32(s/ms)             | time                     |
| time64(us/ns)            | time                     |
| timestamp(s/ms/us/ns+tz) | datetimeoffset           |
| null                     | varbinary(max)           |

## SQL Server to Arrow

| SQL Server               | Arrow                    |
| ------------------------ | ------------------------ |
| (n)(var)char             | utf8                     |
| (n)text                  | utf8                     |
| variant                  | utf8                     |
| (var)binary              | binary                   |
| user defined type        | binary                   |
| uniqueidentifier         | fixedbinary(16)          |
| decimal(p, s)            | decimal128(p, s) or null |
| numeric(p, s)            | decimal128(p, s) or null |
| (small)money             | decimal128               |
| bit                      | boolean                  |
| tinyint                  | uint8                    |
| smallint                 | int16                    |
| int                      | int32                    |
| bigint                   | int64                    |
| real                     | float32                  |
| float                    | float64                  |
| date                     | date32                   |
| (small)datetime          | timestamp(us)            |
| datetime2                | timestamp(us)            |
| time                     | time64(ns)               |
| datetimeoffset           | timestamp(us+tz) or null |

# Limitations
## Reading data from SQL Server
### Decimals / timestamps with timezones

In both Arrow and SQL Server's format, decimal size/precision and timezone offset are part of the column's datatype. However, bcp does not provide this information as metadata and instead specifies it separately for each cell (even though all cells must match). As a consequence, the datatype of an Arrow decimal/timezone column is only known once the first non-`null` cell is read. If all cells are `null`, we don't get this information, so the entire datatype is set to `null` as a workaround. This may lead to issues when another datatype is expected.

### Datetime2 / datetimeoffset

Both of these datatypes store time with an accuracy of 100ns. However Arrow only offers datatype with accuracy 1ns or 1000ns (1us) and both have tradeoffs. The 1ns datatype cannot represent larger values like `'9999-12-31'` and the 1000ns datatype truncates the last digit, i.e. `'9999-12-31 11:11:11.1234567'` turns to `'9999-12-31 11:11:11.1234560'`. This library chooses to truncate.

# Acknowledgements

Thanks to Adam Serafini for figuring out the build process for Zig extensions and providing an [example module](https://github.com/adamserafini/zaml). He explains that it was quite a journey in his [talk](https://www.youtube.com/watch?v=O0MmmZxdct4), which I appreciate, as even just figuring out that targeting `x86_64-windows` instead of `x86_64-windows-msvc` works better for Windows compilation took me several hours.
