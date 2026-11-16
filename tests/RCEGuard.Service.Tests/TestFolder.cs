namespace RCEGuard.Service.Tests;

/// <summary>Removes the data folder of a test.</summary>
internal static class TestFolder
{
    /// <summary>
    /// Deletes the folder with the findings database in it. SQLite keeps closed connections in a
    /// pool, and the test classes run side by side and all empty that pool: once in a while the
    /// file was still held when the folder was deleted (seen once, 2026-11-16). So the delete is
    /// tried again for a moment before it counts as failed.
    /// </summary>
    public static void Delete(string folder)
    {
        for (var attempt = 1; ; attempt++)
        {
            Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();
            try
            {
                Directory.Delete(folder, recursive: true);
                return;
            }
            catch (IOException) when (attempt < 20)
            {
                Thread.Sleep(100);
            }
        }
    }
}
