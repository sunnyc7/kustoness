# An implementation of coalesce operator for Alert enrichment.

## Context/Issue:
- When dealing with [malware alerts](https://learn.microsoft.com/en-us/defender-xdr/investigate-alerts?tabs=settings) from MDCA(MCAS), you might notice that there are 3 line-item events for the same AlertID.
  - The three line-items are for each of the `EntityType:` User, CloudApplication and File.
- This is one of the pecularities you'd encounter for MCAS alerts.
  - The MCAS API logs 3 events per-file and uses a `MergeByKey` and `MergeByKeyHex` to group these events into 1 `AlertId`.
  - I was unable to find any documentation for MergeByKey and MergeByKeyHex. The reader may have more success.
- The issue:
  - The file details (FileName, SHAs) are not in the `EntityType: CloudApplication`
  - The detection source data is not in the `EntityType: File`
- The problem boils down to creating a neat summary of alerts by source with the corresponding file entity-type data with the detection source in the same row.
- The following KQL Query might help you do that.


## KQL:

```
// Author: Sunny Chakraborty. (@sunnyc7)
// Date: 07/29/2024
//
let _title = "Malware dete"
let _window = 30d;
AlertInfo
| where Timestamp > ago(_window) and Title has_any (_title)
| join AlertEvidence on AlertId
| where Timestamp1 > ago(_window)
| where EntityType != "User"
| sort by Timestamp desc
| extend FileNameResolved = iff(isempty(FileName),prev(FileName),FileName)
| extend SHA1Resolved = iff(isempty(SHA1),prev(SHA1),SHA1)
| extend SHA256Resolved = iff(isempty(SHA256),prev(SHA256),SHA256)
| where isnotempty(FileNameResolved) and EntityType == "CloudApplication"
| project-away FileName, SHA1, SHA256

```

## Commentary:
- I played with the [Coalesce](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/coalesce-function) function and it didn't work the way I expected to.
- The insight was to [sort](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/sort-operator) the events by Timestamp, and use the [prev](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/prev-function) operator.
- PS: The terms operator and functions in KQL has been used interchangably.
 
## Reference:

### Product:
- Defender XDR
 
### Schema
- [AlertInfo](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertinfo-table)
- [AlertEvidence](https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-alertevidence-table)
