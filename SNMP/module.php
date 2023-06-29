<?php

declare(strict_types=1);
include_once __DIR__ . '/../libs/vendor/autoload.php';
use FreeDSx\Snmp\SnmpClient;

// SNMP is already in use by the PHP Class: https://www.php.net/manual/en/class.snmp.php
class SNMPWalk extends IPSModule
{
    private $OIDCache = null;

    public function Create()
    {
        //Never delete this line!
        parent::Create();

        //General Properties
        $this->RegisterPropertyString('Host', '');
        $this->RegisterPropertyInteger('Version', 3);
        $this->RegisterPropertyString('StartAt', '1.3.6.1.4');

        //Only applicable to Version 2
        $this->RegisterPropertyString('Community', '');

        //Only applicable to Version 3
        $this->RegisterPropertyString('User', '');

        $this->RegisterPropertyBoolean('AuthenticationEnabled', false);
        $this->RegisterPropertyString('AuthenticationPassword', '');
        $this->RegisterPropertyString('AuthenticationMechanism', 'md5');

        $this->RegisterPropertyBoolean('PrivacyEnabled', false);
        $this->RegisterPropertyString('PrivacyPassword', '');
        $this->RegisterPropertyString('PrivacyMechanism', 'aes128');

        // MIB = Management Information Base
        // Use this tool to convert MIB files to our supported OIDLib: https://www.paessler.com/tools/mibimporter
        $this->RegisterPropertyString('OIDLibs', '[]');

        // Only show OIDs if we have it in our OIDLibs structure
        $this->RegisterPropertyBoolean('OnlyShowKnownOIDs', false);

        $this->RegisterPropertyInteger('TimerInterval', 0);

        // Buffer for internal state and caching
        $this->SetBuffer('IsWalking', 'no');
        $this->SetBuffer('OIDCache', '{}');

        // Timer for refreshing the OID values
        $this->RegisterTimer('UpdateValues', 0, 'SNMP_UpdateValues($_IPS[\'TARGET\']);');
    }

    public function Destroy()
    {
        //Never delete this line!
        parent::Destroy();
    }

    public function ApplyChanges()
    {
        //Never delete this line!
        parent::ApplyChanges();

        // Update the timer with our new Interval
        $this->SetTimerInterval('UpdateValues', $this->ReadPropertyInteger('TimerInterval') * 1000);
    }

    public function GetConfigurationForm()
    {
        $host = $this->ReadPropertyString('Host');
        $version = $this->ReadPropertyInteger('Version');
        $authenticationEnabled = $this->ReadPropertyBoolean('AuthenticationEnabled');
        $privacyEnabled = $this->ReadPropertyBoolean('PrivacyEnabled');

        $data = json_decode(file_get_contents(__DIR__ . '/form.json'));
        $data->elements[0]->expanded = (strlen($host) == 0);
        $data->elements[0]->items[3]->visible = ($version == 1) || ($version == 2);
        $data->elements[0]->items[4]->visible = ($version == 3);
        $data->elements[0]->items[5]->visible = ($version == 3);
        $data->elements[0]->items[6]->visible = ($version == 3) && $authenticationEnabled;
        $data->elements[0]->items[7]->visible = ($version == 3) && $authenticationEnabled;
        $data->elements[0]->items[8]->visible = ($version == 3);
        $data->elements[0]->items[9]->visible = ($version == 3) && $privacyEnabled;
        $data->elements[0]->items[10]->visible = ($version == 3) && $privacyEnabled;

        return json_encode($data);
    }

    public function UIUpdateVersion(int $Version)
    {
        $authenticationEnabled = $this->ReadPropertyBoolean('AuthenticationEnabled');
        $privacyEnabled = $this->ReadPropertyBoolean('PrivacyEnabled');

        $this->UpdateFormField('Community', 'visible', ($Version == 1) || ($Version == 2));
        $this->UpdateFormField('User', 'visible', ($Version == 3));
        $this->UpdateFormField('AuthenticationEnabled', 'visible', ($Version == 3));
        $this->UpdateFormField('AuthenticationPassword', 'visible', ($Version == 3) && $authenticationEnabled);
        $this->UpdateFormField('AuthenticationMechanism', 'visible', ($Version == 3) && $authenticationEnabled);
        $this->UpdateFormField('PrivacyEnabled', 'visible', ($Version == 3));
        $this->UpdateFormField('PrivacyPassword', 'visible', ($Version == 3) && $privacyEnabled);
        $this->UpdateFormField('PrivacyMechanism', 'visible', ($Version == 3) && $privacyEnabled);
    }

    public function UIUpdateAuthentication(bool $AuthenticationEnabled)
    {
        $this->UpdateFormField('AuthenticationPassword', 'visible', $AuthenticationEnabled);
        $this->UpdateFormField('AuthenticationMechanism', 'visible', $AuthenticationEnabled);
    }

    public function UIUpdatePrivacy(bool $PrivacyEnabled)
    {
        $this->UpdateFormField('PrivacyPassword', 'visible', $PrivacyEnabled);
        $this->UpdateFormField('PrivacyMechanism', 'visible', $PrivacyEnabled);
    }

    public function StartWalkingOIDs()
    {
        if (!$this->ReadPropertyString('Host')) {
            echo $this->Translate('Please configure Host before starting a walk!');
            return;
        }
        $this->SetBuffer('IsWalking', 'yes');

        $this->UpdateOIDCache();

        $snmp = $this->createSNMPClient();
        $walk = $snmp->walk($this->ReadPropertyString('StartAt'));

        // At this point we have at least some sort of communication going
        // Update progressbar and buttons
        $this->UpdateFormField('Bar', 'caption', $this->Translate('Walking...'));
        $this->UpdateFormField('Bar', 'indeterminate', true);
        $this->UpdateFormField('Bar', 'maximum', 1);
        $this->UpdateFormField('Bar', 'current', 0);

        // Create a cache of all previously created Idents for faster "Active?" evaluation
        $childrenIdents = [];
        foreach (IPS_GetChildrenIDs($this->InstanceID) as $id) {
            if (IPS_VariableExists($id)) {
                $childrenIdents[IPS_GetObject($id)['ObjectIdent']] = IPS_GetVariable($id)['VariableAction'] > 0;
            }
        }

        // Initialize variable for list values
        $values = [];

        // Counter for our progressbar
        $count = 0;

        // Get the memory limit of php
        $inBytes = function ($memoryLimit): int
        {
            preg_match('/([0-9]+)[\s]*([a-zA-Z]+)/', $memoryLimit, $matches);
            $value = (isset($matches[1])) ? $matches[1] : 0;
            $metric = (isset($matches[2])) ? strtolower($matches[2]) : 'b';

            switch ($metric) {
                case 'k':
                case 'kb':
                    $value *= 1024;
                    break;
                case 'm':
                case 'mb':
                    $value *= (1024 ** 2);
                    break;
                case 'g':
                case 'gb':
                    $value *= (1024 ** 3);
                    break;
                case't':
                case 'tb':
                    $value *= (1024 ** 4);
                    break;
                default:
                    $value = 0;
                    break;
            }
            return intval($value);
        };
        $memoryMaxSize = $inBytes(ini_get('memory_limit'));

        try {
            // Keep the walk going until there are no more OIDs left OR the memory usage is on 80 %
            while ($walk->hasOids() && (memory_get_usage(true) / $memoryMaxSize < 0.8)) {
                $this->UpdateFormField('Bar', 'caption', sprintf($this->Translate('Walking... %d'), ++$count));

                // Abort walk if IsWalking is set to false
                if ($this->GetBuffer('IsWalking') != 'yes') {
                    break;
                }

                // Get the next OID in the walk
                $oid = $walk->next();

                $value = ['OID' => $oid->getOID()];

                // Check if we have more details in our OID cache
                $info = $this->getInformationFromOIDCache($oid->getOID());
                if ($info) {
                    $value['Name'] = $info['Name'];
                    $value['Description'] = $info['Description'];
                } else {
                    // Skip OIDs that are unknown if we only want known ones
                    if ($this->ReadPropertyBoolean('OnlyShowKnownOIDs')) {
                        continue;
                    }
                    $value['Name'] = '';
                    $value['Description'] = '';
                }

                // Create Ident by replacing all dots with underscores
                $ident = $this->OIDtoIdent($oid->getOID());
                $value['Active'] = isset($childrenIdents[$ident]);
                $value['Writeable'] = isset($childrenIdents[$ident]) && $childrenIdents[$ident];

                // Convert to HEX if it is not a valid UTF-8 value
                $value['Value'] = strval($oid->getValue());
                if (!$this->isValidUTF8($value['Value'])) {
                    $value['Value'] = bin2hex($value['Value']);
                }

                $values[] = $value;
            }

            $this->UpdateFormField('OIDList', 'values', json_encode($values));

            $this->UpdateFormField('Bar', 'indeterminate', false);
            $this->UpdateFormField('Bar', 'current', 1);
            $this->UpdateFormField('Count', 'caption', sprintf($this->Translate('%d OIDs in the list.'), count($values)));
        } catch (\Exception $e) {
            // If we have an issue, display it here (network timeout, etc)
            echo $e->getMessage();
        }

        $this->SetBuffer('IsWalking', 'no');
    }

    public function StopWalkingOIDs()
    {
        $this->SetBuffer('IsWalking', 'no');
    }

    public function UpdateValues()
    {
        $children = IPS_GetChildrenIDs($this->InstanceID);

        $snmp = $this->createSNMPClient();

        foreach ($children as $child) {
            $objectIdent = IPS_GetObject($child)['ObjectIdent'];
            try {
                $value = $snmp->getValue($this->IdentToOID($objectIdent));
                $this->SetValue($objectIdent, $value);
            } catch (\Exception $e) {
                // If we have an issue, display it here (network timeout, etc)
                echo $e->getMessage();
            }
        }
    }

    public function CreateVariable(object $value)
    {
        $ident = $this->OIDtoIdent($value['OID']);
        if ($value['Active']) {
            $name = $value['Name'] ? sprintf('%s (%s)', $value['Name'], $value['OID']) : $value['OID'];
            if (is_numeric($value['Value'])) {
                $this->RegisterVariableFloat($ident, $name);
            } else {
                $this->RegisterVariableString($ident, $name);
            }
            if ($value['Writable']) {
                $this->EnableAction($ident);
            } else {
                $this->DisableAction($ident);
            }
            $this->SetValue($ident, $value['Value']);
        } else {
            $this->UnregisterVariable($ident);
        }
    }

    public function UpdateOIDCache()
    {
        $list = json_decode($this->ReadPropertyString('OIDLibs'), true);

        if (count($list) == 0) {
            return;
        }

        $startOID = $this->ReadPropertyString('StartAt');
        $OIDs = [];
        foreach ($list as $row) {
            $xml = simplexml_load_string(base64_decode($row['File']));
            foreach ($xml->list->entry as $entry) {
                // Check if the buffer is under 1024 kb
                if (strlen(json_encode($OIDs, JSON_FORCE_OBJECT)) * 8 / 1024 > 1024) {
                    $this->UpdateFormField('Alert', 'visible', true);
                    $this->UpdateFormField('AlertLabel', 'caption', $this->Translate('To many OIDs in the OIDLib'));
                    $this->SetBuffer('IsWalking', 'no');
                    break;
                }

                //Only add OIDs in the space of the start OID
                $oid = trim(strval($entry->oid));
                if (strpos($oid, $startOID) !== false) {
                    $name = trim(strval($entry->indicator));
                    $description = trim(strval($entry->description));

                    $OIDs[$oid] = [
                        'Name'        => $name,
                        'Description' => $description
                    ];
                }
            }
        }
        $this->SetBuffer('OIDCache', json_encode($OIDs, JSON_FORCE_OBJECT));

        // Reset fast internal cache
        $this->OIDCache = null;
    }

    public function RequestAction($Ident, $Value)
    {
        $oid = $this->IdentToOID($Ident);
        $snmp = $this->createSNMPClient();

        try {
            $oidObject = $snmp->getOid($oid);

            if ($oidObject->getValue() instanceof FreeDSx\Snmp\Value\StringValue) {
                $snmp->set(\FreeDSx\Snmp\Oid::fromString($oid, $Value));
            } elseif ($oidObject->getValue() instanceof FreeDSx\Snmp\Value\IntegerValue) {
                $snmp->set(\FreeDSx\Snmp\Oid::fromInteger($oid, $Value));
            } elseif ($oidObject->getValue() instanceof FreeDSx\Snmp\Value\UnsignedIntegerValue) {
                $snmp->set(\FreeDSx\Snmp\Oid::fromUnsignedInt($oid, $Value));
            } elseif ($oidObject->getValue() instanceof FreeDSx\Snmp\Value\CounterValue) {
                $snmp->set(\FreeDSx\Snmp\Oid::fromCounter($oid, $Value));
            } elseif ($oidObject->getValue() instanceof FreeDSx\Snmp\Value\BigCounterValue) {
                $snmp->set(\FreeDSx\Snmp\Oid::fromBigCounter($oid, $Value));
            } else {
                throw new Exception('Unsupported Type: ' . get_class($oidObject->getValue()));
            }
        } catch (\Exception $e) {
            // If we have an issue, display it here (network timeout, etc)
            echo $e->getMessage();
        }

        $this->SetValue($Ident, $Value);
    }

    private function getInformationFromOIDCache($oid)
    {
        if (!$this->OIDCache) {
            $this->OIDCache = json_decode($this->GetBuffer('OIDCache'), true);
        }

        // Return the cache entry
        if (isset($this->OIDCache[$oid])) {
            return $this->OIDCache[$oid];
        }

        // Cut the last number (partial match is better than nothing)
        $key = substr($oid, 0, strrpos($oid, '.'));

        // Return the cache entry
        if (isset($this->OIDCache[$key])) {
            return $this->OIDCache[$key];
        }

        return null;
    }

    private function OIDtoIdent($oid)
    {
        return str_replace('.', '_', $oid);
    }

    private function IdentToOID($ident)
    {
        return str_replace('_', '.', $ident);
    }

    private function isValidUTF8($string)
    {
        return preg_match('%^(?:
              [\x09\x0A\x0D\x20-\x7E]            # ASCII
            | [\xC2-\xDF][\x80-\xBF]             # non-overlong 2-byte
            | \xE0[\xA0-\xBF][\x80-\xBF]         # excluding overlongs
            | [\xE1-\xEC\xEE\xEF][\x80-\xBF]{2}  # straight 3-byte
            | \xED[\x80-\x9F][\x80-\xBF]         # excluding surrogates
            | \xF0[\x90-\xBF][\x80-\xBF]{2}      # planes 1-3
            | [\xF1-\xF3][\x80-\xBF]{3}          # planes 4-15
            | \xF4[\x80-\x8F][\x80-\xBF]{2}      # plane 16
        )*$%xs', $string);
    }

    private function createSNMPClient()
    {
        $configuration = [
            'host'      => $this->ReadPropertyString('Host'),
            'version'   => $this->ReadPropertyInteger('Version'),
        ];
        switch ($configuration['version']) {
            case 1:
            case 2:
                $configuration['community'] = $this->ReadPropertyString('Community');
                break;
            case 3:
                $configuration['user'] = $this->ReadPropertyString('User');
                if ($this->ReadPropertyBoolean('AuthenticationEnabled')) {
                    $configuration['use_auth'] = true;
                    $configuration['auth_mech'] = $this->ReadPropertyString('AuthenticationMechanism');
                    $configuration['auth_pwd'] = $this->ReadPropertyString('AuthenticationPassword');
                }
                if ($this->ReadPropertyBoolean('PrivacyEnabled')) {
                    $configuration['use_priv'] = true;
                    $configuration['priv_mech'] = $this->ReadPropertyString('PrivacyMechanism');
                    $configuration['priv_pwd'] = $this->ReadPropertyString('PrivacyPassword');
                }
                break;
        }
        return new SnmpClient($configuration);
    }
}
