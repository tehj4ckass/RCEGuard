using RCEGuard.Core.Sysmon;

namespace RCEGuard.Core.Tests;

public sealed class LogResumeTests
{
    private static readonly DateTimeOffset T0 = new(2026, 11, 12, 18, 0, 0, TimeSpan.Zero);

    private static LogPosition At(long recordId) => new(recordId, T0.AddSeconds(recordId));

    [Fact]
    public void Without_a_saved_position_only_new_events_are_read()
    {
        var plan = LogResume.Decide(saved: null, At(1), At(500), timeOfSavedRecord: null);

        Assert.Equal(new ResumePlan(ResumeKind.FirstStart, StartAfterRecordId: 500, Pending: 0, Lost: 0), plan);
    }

    [Fact]
    public void Without_a_saved_position_an_empty_log_is_read_from_its_start()
    {
        var plan = LogResume.Decide(saved: null, oldest: null, newest: null, timeOfSavedRecord: null);

        Assert.Equal(new ResumePlan(ResumeKind.FirstStart, 0, 0, 0), plan);
    }

    [Fact]
    public void Nothing_written_since_the_saved_position_leaves_nothing_to_catch_up()
    {
        var plan = LogResume.Decide(At(500), At(1), At(500), At(500).TimeCreated);

        Assert.Equal(new ResumePlan(ResumeKind.Resume, 500, Pending: 0, Lost: 0), plan);
    }

    [Fact]
    public void Events_written_after_the_saved_position_are_pending()
    {
        var plan = LogResume.Decide(At(500), At(1), At(540), At(500).TimeCreated);

        Assert.Equal(new ResumePlan(ResumeKind.Resume, 500, Pending: 40, Lost: 0), plan);
    }

    [Fact]
    public void A_saved_time_that_went_through_a_file_still_matches()
    {
        var saved = At(500);
        var fromLog = saved.TimeCreated.AddTicks(3);

        var plan = LogResume.Decide(saved, At(1), At(540), fromLog);

        Assert.Equal(ResumeKind.Resume, plan.Kind);
    }

    [Fact]
    public void The_same_record_id_with_another_time_is_another_log()
    {
        // Sysmon was reinstalled: the new log has a record 500 as well, written at another time.
        var plan = LogResume.Decide(At(500), At(1), At(900), T0.AddHours(3));

        Assert.Equal(new ResumePlan(ResumeKind.LogReplaced, StartAfterRecordId: 0, Pending: 900, Lost: 0), plan);
    }

    [Fact]
    public void A_log_that_ends_before_the_saved_position_is_another_log()
    {
        var plan = LogResume.Decide(At(500), At(1), At(20), timeOfSavedRecord: null);

        Assert.Equal(new ResumePlan(ResumeKind.LogReplaced, 0, Pending: 20, Lost: 0), plan);
    }

    [Fact]
    public void A_saved_position_and_an_empty_log_mean_the_log_was_emptied()
    {
        var plan = LogResume.Decide(At(500), oldest: null, newest: null, timeOfSavedRecord: null);

        Assert.Equal(new ResumePlan(ResumeKind.LogReplaced, 0, 0, 0), plan);
    }

    [Fact]
    public void Overwritten_events_are_counted_as_lost_and_the_rest_is_read()
    {
        // The log wrapped while the guard was down: records 501 to 699 are gone.
        var plan = LogResume.Decide(At(500), At(700), At(1000), timeOfSavedRecord: null);

        Assert.Equal(new ResumePlan(ResumeKind.Overwritten, StartAfterRecordId: 699, Pending: 301, Lost: 199), plan);
    }

    [Fact]
    public void The_saved_event_may_be_gone_as_long_as_the_next_one_is_there()
    {
        var plan = LogResume.Decide(At(500), At(501), At(520), timeOfSavedRecord: null);

        Assert.Equal(new ResumePlan(ResumeKind.Resume, 500, Pending: 20, Lost: 0), plan);
    }
}
