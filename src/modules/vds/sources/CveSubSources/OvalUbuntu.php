<?php

require_once(realpath(dirname(__FILE__)) . '/../../include/ISubSource.php');
require_once(realpath(dirname(__FILE__)) . '/../../lib/SubSource.php');

/**
 * Ubuntu CVE OVAL (com.ubuntu.<codename>.cve.oval.xml).
 *
 * A definition's criterion names a *source* package, while hosts report *binary*
 * packages. The binaries and the fixed version are therefore taken from the
 * referenced dpkginfo test: object -> constant_variable (binary names) and
 * state -> evr "less than" (fixed version). Criterion comments are not parsed,
 * as their wording has changed between feed generations.
 *
 * Tests without a state (CVE not fixed yet) and kernel tests (uname/variable
 * tests, keyed on the running kernel flavour) carry no comparable package
 * version and are skipped.
 */
class OvalUbuntu extends SubSource implements ISubSource
{
    protected static $NAME = "Ubuntu OVAL";
    protected static $TYPE = "Ubuntu";

    private static $NS_DEF = "http://oval.mitre.org/XMLSchema/oval-definitions-5";
    private static $NS_LINUX = "http://oval.mitre.org/XMLSchema/oval-definitions-5#linux";

    public function processAdvisories($contents, $subSourceDef_id)
    {
        $oval = new DOMDocument();
        if ($oval->loadXML($contents, LIBXML_PARSEHUGE) === false) {
            Utils::log(LOG_ERR, "Cannot load OVAL for $subSourceDef_id", __FILE__, __LINE__);
            throw new Exception("Cannot load OVAL for $subSourceDef_id");
        }

        $xp = new DOMXPath($oval);
        $xp->registerNamespace("def", self::$NS_DEF);
        $xp->registerNamespace("lin", self::$NS_LINUX);

        # variable id -> binary package names
        $variables = array();
        foreach ($xp->query('/def:oval_definitions/def:variables/def:constant_variable') as $xVar) {
            $values = array();
            foreach ($xp->query('def:value', $xVar) as $xValue) {
                $values[] = trim($xValue->nodeValue);
            }
            $variables[$xVar->getAttribute('id')] = $values;
        }

        # object id -> binary package names
        $objects = array();
        foreach ($xp->query('/def:oval_definitions/def:objects/lin:dpkginfo_object') as $xObj) {
            $xName = $xp->query('lin:name', $xObj)->item(0);
            if ($xName === null) {
                continue;
            }
            if ($xName->hasAttribute('var_ref')) {
                $varRef = $xName->getAttribute('var_ref');
                $objects[$xObj->getAttribute('id')] = isset($variables[$varRef]) ? $variables[$varRef] : array();
            } else {
                $objects[$xObj->getAttribute('id')] = array(trim($xName->nodeValue));
            }
        }

        # state id -> fixed version
        $states = array();
        foreach ($xp->query('/def:oval_definitions/def:states/lin:dpkginfo_state') as $xState) {
            $xEvr = $xp->query('lin:evr', $xState)->item(0);
            if ($xEvr !== null && $xEvr->getAttribute('operation') == "less than") {
                $states[$xState->getAttribute('id')] = trim($xEvr->nodeValue);
            }
        }

        # test id -> list of vulnerable packages
        $tests = array();
        foreach ($xp->query('/def:oval_definitions/def:tests/lin:dpkginfo_test') as $xTest) {
            $xObj = $xp->query('lin:object', $xTest)->item(0);
            $xState = $xp->query('lin:state', $xTest)->item(0);
            if ($xObj === null || $xState === null) {
                continue;
            }
            $objRef = $xObj->getAttribute('object_ref');
            $stateRef = $xState->getAttribute('state_ref');
            if (empty($objects[$objRef]) || !isset($states[$stateRef])) {
                continue;
            }

            # Debian version: [epoch:]upstream[-revision], the revision follows the last dash
            $fixed = $states[$stateRef];
            $pos = strrpos($fixed, '-');
            $version = ($pos === false) ? $fixed : substr($fixed, 0, $pos);
            $release = ($pos === false) ? "" : substr($fixed, $pos + 1);

            $pkgs = array();
            foreach ($objects[$objRef] as $binary) {
                $pkgs[] = array('name' => $binary, 'version' => $version, 'release' => $release, 'operator' => '<');
            }
            $tests[$xTest->getAttribute('id')] = $pkgs;
        }
        unset($variables, $objects, $states);

        $defs = array();
        $xDefinitions = $xp->query('/def:oval_definitions/def:definitions/def:definition[@class="vulnerability"]');
        foreach ($xDefinitions as $xDefinition) {
            $xPlatform = $xp->query('def:metadata/def:affected/def:platform', $xDefinition)->item(0);
            if ($xPlatform === null) {
                continue;
            }
            $os = trim($xPlatform->nodeValue);

            $pkgs = array();
            foreach ($xp->query('.//def:criterion', $xDefinition) as $xCriterion) {
                $testRef = $xCriterion->getAttribute('test_ref');
                if (isset($tests[$testRef])) {
                    $pkgs = array_merge($pkgs, $tests[$testRef]);
                }
            }
            if (empty($pkgs)) {
                continue;
            }

            $cves = array();
            $refUrl = "";
            foreach ($xp->query('def:metadata/def:reference[@source="CVE"]', $xDefinition) as $xRef) {
                $cves[] = $xRef->getAttribute('ref_id');
                if ($refUrl == "") {
                    $refUrl = $xRef->getAttribute('ref_url');
                }
            }

            $xSeverity = $xp->query('def:metadata/def:advisory/def:severity', $xDefinition)->item(0);

            $def = array();
            $def['subSourceDefId'] = $subSourceDef_id;
            $def['definition_id'] = $xDefinition->getAttribute('id');
            $def['severity'] = ($xSeverity !== null) ? $xSeverity->nodeValue : "n/a";
            $def['title'] = rtrim($xp->query('def:metadata/def:title', $xDefinition)->item(0)->nodeValue);
            $def['ref_url'] = $refUrl;
            $def['cves'] = $cves;
            $def['os'] = array($os);
            $def['osGroup'] = array($os => $pkgs);
            $defs[] = $def;
        }

        return $defs;
    }
}
