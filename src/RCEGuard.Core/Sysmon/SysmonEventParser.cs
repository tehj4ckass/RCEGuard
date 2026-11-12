using System.Globalization;
using System.Xml;
using System.Xml.Linq;

namespace RCEGuard.Core.Sysmon;

/// <summary>Parses the XML form of a Windows event (EventRecord.ToXml) into a <see cref="SysmonEvent"/>.</summary>
public static class SysmonEventParser
{
    private static readonly XNamespace Ns = "http://schemas.microsoft.com/win/2004/08/events/event";

    /// <summary>Parses one event. Throws <see cref="FormatException"/> if the XML is not a usable event.</summary>
    public static SysmonEvent Parse(string xml)
    {
        if (!TryParse(xml, out var result, out var error))
        {
            throw new FormatException(error);
        }

        return result!;
    }

    /// <summary>Parses one event without throwing; <paramref name="error"/> says what was wrong.</summary>
    public static bool TryParse(string xml, out SysmonEvent? result, out string error)
    {
        result = null;
        XElement root;
        try
        {
            root = XElement.Parse(xml);
        }
        catch (XmlException ex)
        {
            error = $"Event is not well-formed XML: {ex.Message}";
            return false;
        }

        var system = root.Element(Ns + "System");
        var eventData = root.Element(Ns + "EventData");
        if (root.Name != Ns + "Event" || system is null || eventData is null)
        {
            error = "Event XML has no System or EventData block.";
            return false;
        }

        if (!int.TryParse(system.Element(Ns + "EventID")?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var eventId))
        {
            error = "Event XML has no numeric EventID.";
            return false;
        }

        _ = long.TryParse(system.Element(Ns + "EventRecordID")?.Value, NumberStyles.Integer, CultureInfo.InvariantCulture, out var recordId);

        var timeText = system.Element(Ns + "TimeCreated")?.Attribute("SystemTime")?.Value;
        if (!DateTimeOffset.TryParse(timeText, CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var time))
        {
            error = "Event XML has no readable TimeCreated.";
            return false;
        }

        var data = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        foreach (var item in eventData.Elements(Ns + "Data"))
        {
            var name = item.Attribute("Name")?.Value;
            if (!string.IsNullOrEmpty(name))
            {
                data[name] = item.Value;
            }
        }

        result = new SysmonEvent(eventId, recordId, time, data);
        error = string.Empty;
        return true;
    }
}
