<?php

declare(strict_types=1);
include_once __DIR__ . '/../libs/vendor/autoload.php';
use FreeDSx\Snmp\SnmpClient;

class SNMP extends IPSModule
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

        $this->UpdateOIDCache();

        $snmp = $this->createSNMPClient();
        $walk = $snmp->walk('1.3.6.1.4');

        // At this point we have at least some sort of communication going
        // Update progressbar and buttons
        $this->SetBuffer('IsWalking', 'yes');
        $this->UpdateFormField('StartWalk', 'visible', false);
        $this->UpdateFormField('StopWalk', 'visible', true);
        $this->UpdateFormField('Bar', 'caption', $this->Translate('Walking...'));
        $this->UpdateFormField('Bar', 'visible', true);
        $this->UpdateFormField('Bar', 'maximum', 1);
        $this->UpdateFormField('Bar', 'current', 0);

        // Create a cache of all previously created Idents for faster "Active?" evaluation
        $childrenIdents = [];
        foreach (IPS_GetChildrenIDs($this->InstanceID) as $id) {
            $childrenIdents[] = IPS_GetObject($id)['ObjectIdent'];
        }

        // Initialize variable for list values
        $values = [];

        // Counter for our progressbar
        $count = 0;

        try {
            // Keep the walk going until there are no more OIDs left
            while ($walk->hasOids()) {
                $this->UpdateFormField('Bar', 'caption', sprintf($this->Translate('Walking... %d'), ++$count));

                // Abort walk if IsWalking is set to false
                if ($this->GetBuffer('IsWalking') != 'yes') {
                    break;
                }

                // Get the next OID in the walk
                $oid = $walk->next();

                // Create Ident by replacing all dots with underscores
                $ident = str_replace('.', '_', $oid->getOID());

                // Convert to HEX if it is not a valid UTF-8 value
                $value = strval($oid->getValue());
                if (!$this->isValidUTF8($value)) {
                    $value = bin2hex($value);
                }

                $value = [
                    'OID'         => $oid->getOID(),
                    'Name'        => '',
                    'Description' => '',
                    'Value'       => $value,
                    'Active'      => in_array($ident, $childrenIdents),
                ];

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
                }

                $values[] = $value;
            }

            $this->UpdateFormField('OIDList', 'values', json_encode($values));
        } catch (\Exception $e) {
            // If we have an issue, display it here (network timeout, etc)
            echo $e->getMessage();
        }

        $this->SetBuffer('IsWalking', 'no');
        $this->UpdateFormField('Bar', 'visible', false);
        $this->UpdateFormField('StartWalk', 'visible', true);
        $this->UpdateFormField('StopWalk', 'visible', false);
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
            $ident = str_replace('_', '.', $objectIdent);
            $value = $snmp->getValue($ident);

            $this->SetValue($objectIdent, $value);
        }
    }

    public function CreateVariable(object $value)
    {
        $ident = str_replace('.', '_', $value['OID']);
        if ($value['Active']) {
            $name = $value['Name'] ? sprintf('%s (%s)', $value['Name'], $value['OID']) : $value['OID'];
            if (is_numeric($value['Value'])) {
                $this->RegisterVariableFloat($ident, $name);
            } else {
                $this->RegisterVariableString($ident, $name);
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

        $OIDs = [];
        foreach ($list as $row) {
            $xml = simplexml_load_string(base64_decode($row['File']));
            foreach ($xml->list->entry as $entry) {
                $oid = trim(strval($entry->oid));
                $name = trim(strval($entry->indicator));
                $description = trim(strval($entry->description));

                $OIDs[$oid] = [
                    'Name'        => $name,
                    'Description' => $description
                ];
            }
        }
        $this->SetBuffer('OIDCache', json_encode($OIDs, JSON_FORCE_OBJECT));

        // Reset fast internal cache
        $this->OIDCache = null;
    }

    private function getInformationFromOIDCache($oid)
    {
        if (!$this->OIDCache) {
            $this->OIDCache = json_decode($this->GetBuffer('OIDCache'), true);
        }

        // Cut the last number
        $key = substr($oid, 0, strrpos($oid, '.'));

        // Return the cache entry
        if (isset($this->OIDCache[$key])) {
            return $this->OIDCache[$key];
        }

        return null;
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
