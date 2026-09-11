using System;
using System.IO;
using Microsoft.EntityFrameworkCore;
using IPsecSecurityAnalyzer.Data.Entities;

namespace IPsecSecurityAnalyzer.Data;

/// <summary>
/// Entity Framework Core SQLite database context for VPNGuard audit history.
/// Database file defaults to Data/vpnguard.db in the application directory.
/// </summary>
public class AppDbContext : DbContext
{
    public DbSet<AnalysisHistoryEntity> AnalysisHistories => Set<AnalysisHistoryEntity>();

    public string DbPath { get; }

    public AppDbContext()
    {
        var appDataDir = AppDomain.CurrentDomain.BaseDirectory;
        var dataFolder = Path.Combine(appDataDir, "Data");
        if (!Directory.Exists(dataFolder))
        {
            Directory.CreateDirectory(dataFolder);
        }
        DbPath = Path.Combine(dataFolder, "vpnguard.db");
    }

    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
        DbPath = string.Empty;
    }

    protected override void OnConfiguring(DbContextOptionsBuilder optionsBuilder)
    {
        if (!optionsBuilder.IsConfigured)
        {
            optionsBuilder.UseSqlite($"Data Source={DbPath}");
        }
    }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<AnalysisHistoryEntity>(entity =>
        {
            entity.HasKey(e => e.Id);
            entity.HasIndex(e => e.AnalysisId).IsUnique();
            entity.HasIndex(e => e.AnalysisDate);
            entity.Property(e => e.FileName).IsRequired().HasMaxLength(260);
            entity.Property(e => e.FilePath).HasMaxLength(500);
            entity.Property(e => e.SnapshotJson).IsRequired();
        });
    }
}
