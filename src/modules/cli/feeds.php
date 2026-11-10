#!/usr/bin/php
<?php

/*
 * Registers the vulnerability feed of every OS group that has reporting hosts,
 * following Config::$VDS_FEEDS. A feed is registered only when its URI answers.
 * Prints registrations, coverage gaps and feeds not refreshed for 2 days; prints nothing
 * when there is nothing to do,
 * so it can run from cron with mail on output.
 */

require(realpath(dirname(__FILE__)) . '/../../common/Loader.php');
require(realpath(dirname(__FILE__)) . '/../vds/VdsModule.php');

$shortopts = "c:hn";
$longopts = array(
    "config:",          # Config file - N.B. handled in Loader.php
    "help",
    "dry-run",
);

function usage()
{
    die("Usage: feeds [-h|--help] [-n|--dry-run] -c discover|list\n" .
        "  discover  register the missing feeds of the OS groups that have hosts\n" .
        "  list      show OS groups with hosts and the feed each one maps to\n");
}

$opt = getopt($shortopts, $longopts);
if (isset($opt["h"]) || isset($opt["help"]) || !isset($opt["c"])) {
    usage();
}
$cmd = $opt["c"];
$dryRun = isset($opt["n"]) || isset($opt["dry-run"]);
if ($cmd != "discover" && $cmd != "list") {
    usage();
}

/* Feed for an OS group name, or null when no rule applies */
function feedFor($osGroupName)
{
    foreach (Config::$VDS_FEEDS as $regex => $feed) {
        if (preg_match($regex, $osGroupName, $m) != 1) {
            continue;
        }
        list($subSourceName, $defName, $uri) = $feed;
        for ($i = count($m) - 1; $i >= 1; $i--) {
            $defName = str_replace('$' . $i, $m[$i], $defName);
            $uri = str_replace('$' . $i, $m[$i], $uri);
        }
        if (strpos($uri, '{codename}') !== false) {
            if (!isset($m[1]) || !isset(Config::$UBUNTU_CODENAMES[$m[1]])) {
                return array($subSourceName, $defName, null);
            }
            $uri = str_replace('{codename}', Config::$UBUNTU_CODENAMES[$m[1]], $uri);
        }
        return array($subSourceName, $defName, $uri);
    }
    return null;
}

function uriAvailable($uri)
{
    $ch = curl_init($uri);
    curl_setopt($ch, CURLOPT_NOBODY, true);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
    curl_setopt($ch, CURLOPT_TIMEOUT, 60);
    if (Config::$ENABLE_OUTGOING_PROXY == 1) {
        curl_setopt($ch, CURLOPT_PROXY, preg_replace('#^tcp://#', '', Config::$OUTGOING_PROXY));
    }
    curl_exec($ch);
    $code = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
    curl_close($ch);
    return $code == 200;
}

$db = $pakiti->getManager("DbManager");

$vds = new VdsModule($pakiti);
$cveSource = null;
foreach ($vds->getSources() as $source) {
    if ($source->getName() == "Cve") {
        $cveSource = $source;
    }
}
if ($cveSource == null) {
    fwrite(STDERR, "No Cve source registered\n");
    exit(1);
}
$subSources = array();
$registeredUris = array();
foreach ($cveSource->getSubSources() as $subSource) {
    $subSources[$subSource->getName()] = $subSource;
    foreach ($subSource->getSubSourceDefs() as $subSourceDef) {
        $registeredUris[$subSourceDef->getUri()] = true;
    }
}

$warnings = 0;

# Hosts whose OS matches no OS group cannot be evaluated at all
$unmapped = $db->queryToSingleValueMultiRow("select distinct Os.name from Host join Os on Host.osId = Os.id
    left join OsOsGroup on OsOsGroup.osId = Os.id where OsOsGroup.osId is null order by Os.name");
foreach ($unmapped as $osName) {
    fwrite(STDERR, "WARNING: OS '$osName' matches no OS group (extend OS_GROUPS_MAPPING, then run recalculateOsGroupsMapping.php)\n");
    $warnings++;
}

# A failed download is only logged by synchronize, so a dead feed would silently go stale
$stale = $db->queryToMultiRow("select name, uri, lastChecked from VdsSubSourceDef
    where enabled = 1 and lastChecked < now() - interval 2 day order by name");
foreach ((array)$stale as $row) {
    fwrite(STDERR, "WARNING: feed '" . $row["name"] . "' not refreshed since " . $row["lastChecked"] . ": " . $row["uri"] . "\n");
    $warnings++;
}

$osGroups = $db->queryToSingleValueMultiRow("select distinct OsGroup.name from Host
    join OsOsGroup on OsOsGroup.osId = Host.osId join OsGroup on OsGroup.id = OsOsGroup.osGroupId order by OsGroup.name");
foreach ($osGroups as $osGroupName) {
    $feed = feedFor($osGroupName);
    if ($feed === null) {
        fwrite(STDERR, "WARNING: no feed rule for OS group '$osGroupName'\n");
        $warnings++;
        continue;
    }
    list($subSourceName, $defName, $uri) = $feed;
    if ($uri === null) {
        fwrite(STDERR, "WARNING: no codename known for OS group '$osGroupName' (extend UBUNTU_CODENAMES)\n");
        $warnings++;
        continue;
    }
    $registered = isset($registeredUris[$uri]);

    if ($cmd == "list") {
        print "$osGroupName\t$subSourceName\t$uri\t" . ($registered ? "registered" : "missing") . "\n";
        continue;
    }
    if ($registered) {
        continue;
    }
    if (!isset($subSources[$subSourceName])) {
        fwrite(STDERR, "WARNING: subsource '$subSourceName' for OS group '$osGroupName' is not available\n");
        $warnings++;
        continue;
    }
    if (!uriAvailable($uri)) {
        fwrite(STDERR, "WARNING: feed for OS group '$osGroupName' is not available: $uri\n");
        $warnings++;
        continue;
    }
    if ($dryRun) {
        print "Would register '$defName' ($subSourceName): $uri\n";
        continue;
    }
    $subSourceDef = new SubSourceDef();
    $subSourceDef->setName($defName);
    $subSourceDef->setUri($uri);
    $subSourceDef->setSubSourceId($subSources[$subSourceName]->getId());
    $subSources[$subSourceName]->addSubSourceDef($subSourceDef);
    $registeredUris[$uri] = true;
    print "Registered '$defName' ($subSourceName): $uri\n";
}

# Warnings do not fail the run: the following synchronization must still happen
exit(0);
