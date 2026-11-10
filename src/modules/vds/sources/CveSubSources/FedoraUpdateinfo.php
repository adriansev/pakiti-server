<?php

require_once(realpath(dirname(__FILE__)) . '/../../include/ISubSource.php');
require_once(realpath(dirname(__FILE__)) . '/../../lib/SubSource.php');

/**
 * Fedora security updates, taken from the updateinfo metadata of an updates
 * repository. Fedora publishes no OVAL; Bodhi updates reference Bugzilla
 * bugs whose titles carry the CVE identifiers.
 *
 * The subsource definition URI is the repository's repodata/repomd.xml, e.g.
 * https://dl.fedoraproject.org/pub/fedora/linux/updates/44/Everything/x86_64/repodata/repomd.xml
 * Its hash changes on every repository update, which triggers re-processing.
 *
 * Only stable security updates naming at least one CVE are used. The OS group
 * is the update's <release> text ("Fedora 44").
 */
class FedoraUpdateinfo extends SubSource implements ISubSource
{
    protected static $NAME = "Fedora updateinfo";
    protected static $TYPE = "Fedora";

    public function processAdvisories($contents, $subSourceDef_id)
    {
        $uri = $this->getSubSourceDefById($subSourceDef_id)->getUri();
        $base = preg_replace('#repodata/repomd\.xml$#', '', $uri);

        $repomd = new DOMDocument();
        if ($repomd->loadXML($contents) === false) {
            throw new Exception("Cannot load repomd.xml from $uri");
        }
        $xp = new DOMXPath($repomd);
        $xp->registerNamespace("repo", "http://linux.duke.edu/metadata/repo");
        $href = $xp->query('/repo:repomd/repo:data[@type="updateinfo"]/repo:location/@href')->item(0);
        if ($href === null) {
            throw new Exception("No updateinfo in $uri");
        }

        $raw = file_get_contents($base . $href->nodeValue, false, stream_context_create(["http" => ["timeout" => 60*5]]));
        if ($raw === false) {
            throw new Exception("Cannot download " . $base . $href->nodeValue);
        }
        $xml = $this->decompress($raw);
        unset($raw);

        $reader = new XMLReader();
        if (!$reader->XML($xml, null, LIBXML_PARSEHUGE)) {
            throw new Exception("Cannot parse updateinfo from $uri");
        }

        $defs = array();
        while ($reader->read()) {
            if ($reader->nodeType != XMLReader::ELEMENT || $reader->name != "update") {
                continue;
            }
            if ($reader->getAttribute('type') != "security" || $reader->getAttribute('status') != "stable") {
                $reader->next();
                continue;
            }
            $update = simplexml_load_string($reader->readOuterXml());
            $reader->next();
            if ($update === false) {
                continue;
            }

            $cves = array();
            foreach ($update->xpath('references/reference') as $ref) {
                if (preg_match_all('/CVE-\d{4}-\d+/', (string)$ref['title'], $m)) {
                    $cves = array_merge($cves, $m[0]);
                }
            }
            $cves = array_values(array_unique($cves));
            if (empty($cves)) {
                continue;
            }

            # One fixed EVR per package name; architectures are not distinguished
            $pkgs = array();
            foreach ($update->xpath('pkglist/collection/package') as $p) {
                if ((string)$p['arch'] == "src") {
                    continue;
                }
                $epoch = ((string)$p['epoch'] === "") ? "0" : (string)$p['epoch'];
                $pkgs[(string)$p['name']] = array(
                    'name' => (string)$p['name'],
                    'version' => $epoch . ":" . (string)$p['version'],
                    'release' => (string)$p['release'],
                    'operator' => '<',
                );
            }
            if (empty($pkgs)) {
                continue;
            }

            $id = (string)$update->id;
            $os = trim((string)$update->release);
            $def = array();
            $def['subSourceDefId'] = $subSourceDef_id;
            $def['definition_id'] = $id;
            $def['severity'] = ((string)$update->severity === "") ? "n/a" : (string)$update->severity;
            # Multi-package updates list every NVR in the title; CveDef.title is varchar(255)
            $title = $id . ": " . trim((string)$update->title);
            $def['title'] = (strlen($title) > 255) ? substr($title, 0, 252) . "..." : $title;
            $def['ref_url'] = "https://bodhi.fedoraproject.org/updates/" . $id;
            $def['cves'] = $cves;
            $def['os'] = array($os);
            $def['osGroup'] = array($os => array_values($pkgs));
            $defs[] = $def;
        }
        $reader->close();

        return $defs;
    }

    /**
     * Repository metadata is zstd-compressed on current releases; older ones use xz, bzip2 or gzip.
     */
    private function decompress($data)
    {
        $magic = substr($data, 0, 6);
        if (strncmp($magic, "\x28\xb5\x2f\xfd", 4) == 0) {
            return $this->pipe(array("zstd", "-dcq"), $data);
        }
        if (strncmp($magic, "\xfd7zXZ\x00", 6) == 0) {
            return $this->pipe(array("xz", "-dc"), $data);
        }
        if (strncmp($magic, "BZh", 3) == 0) {
            return bzdecompress($data);
        }
        if (strncmp($magic, "\x1f\x8b", 2) == 0) {
            return gzdecode($data);
        }
        return $data;
    }

    private function pipe($cmd, $data)
    {
        # Input from a file and stderr to a file: only stdout is a pipe, so it cannot deadlock
        $in = tempnam(sys_get_temp_dir(), "pakiti_fedora_");
        $err = tempnam(sys_get_temp_dir(), "pakiti_fedora_");
        try {
            if (file_put_contents($in, $data) === false) {
                throw new Exception("Cannot write $in");
            }
            $proc = proc_open($cmd, array(0 => array("file", $in, "r"), 1 => array("pipe", "w"), 2 => array("file", $err, "w")), $pipes);
            if (!is_resource($proc)) {
                throw new Exception("Cannot run " . $cmd[0]);
            }
            $out = stream_get_contents($pipes[1]);
            fclose($pipes[1]);
            if (proc_close($proc) != 0) {
                throw new Exception($cmd[0] . " failed: " . trim(file_get_contents($err)));
            }
            return $out;
        } finally {
            unlink($in);
            unlink($err);
        }
    }
}
