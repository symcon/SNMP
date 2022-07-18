<?php

declare(strict_types=1);
include_once __DIR__ . '/../libs/vendor/autoload.php';
use FreeDSx\Snmp\Exception\SnmpRequestException;
use FreeDSx\Snmp\SnmpClient;

class SNMPAnzeige extends IPSModule
{
    public function Create()
    {
        //Never delete this line!
        parent::Create();

        //Properties
        $this->RegisterPropertyString('Host', '');
        $this->RegisterPropertyInteger('Version', 3);
        $this->RegisterPropertyString('Community', '');

        $this->RegisterPropertyString('User', '');
        $this->RegisterPropertyString('Password', '');
        $this->RegisterPropertyString('AuthMech', 'md5');

        $this->RegisterPropertyBoolean('Private', false);
        $this->RegisterPropertyString('PrivatePassword', '');
        $this->RegisterPropertyString('PrivMech', 'aes128');

        $this->RegisterPropertyString('Mib', '');  //Mib is a shortcut of 'Managment Information Base
        $this->RegisterPropertyBoolean('ShowOidMibMatch', false);

        $this->RegisterPropertyInteger('TimerInterval', 0);
        //Buffer
        $this->SetBuffer('SearchActive', json_encode(true));
        $this->SetBuffer('Mib', json_encode(''));

        //Timer for update
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

        if ($this->ReadPropertyString('Host') != '') {
            $this->setMib();
            $this->prepare();
            //Set a Timer with a new Interval
            $sec = $this->ReadPropertyInteger('TimerInterval') * 1000;
            $this->SetTimerInterval('UpdateValues', $sec);
        }
    }

    public function GetConfigurationForm()
    {
        $this->RegisterOnceTimer('LoadOIds', 'SNMP_prepare($_IPS[\'TARGET\']);');
        $host = $this->ReadPropertyString('Host');
        $version = $this->ReadPropertyInteger('Version');
        $private = $this->ReadPropertyBoolean('Private');

        return json_encode([
            'elements'=> [
                [
                    'type'    => 'ExpansionPanel',
                    'caption' => 'Configuration',
                    'expanded'=> $host == '',
                    'items'   => [

                        [
                            'caption'=> 'Host',
                            'name'   => 'Host',
                            'type'   => 'ValidationTextBox'
                        ],
                        [
                            'type'    => 'Select',
                            'caption' => 'Version',
                            'name'    => 'Version',
                            'onChange'=> 'SNMP_VersionChange($id, $Version);',
                            'options' => [
                                [
                                    'caption'=> '1',
                                    'value'  => 1
                                ],
                                [
                                    'caption'=> '2',
                                    'value'  => 2
                                ],
                                [
                                    'caption'=> '3',
                                    'value'  => 3
                                ]
                            ],
                            'value'=> 3
                        ],
                        [
                            'caption'=> 'Community',
                            'name'   => 'Community',
                            'type'   => 'ValidationTextBox',
                            'visible'=> $version != 3
                        ],
                        [
                            'caption'=> 'User',
                            'name'   => 'User',
                            'type'   => 'ValidationTextBox',
                            'visible'=> $version == 3
                        ],
                        [
                            'caption'=> 'Password',
                            'name'   => 'Password',
                            'type'   => 'PasswordTextBox',
                            'visible'=> $version == 3
                        ],
                        [
                            'caption'=> 'Encryption',
                            'name'   => 'AuthMech',
                            'options'=> [
                                [
                                    'caption'=> 'MD5',
                                    'value'  => 'md5'
                                ],
                                [
                                    'caption'=> 'SHA1',
                                    'value'  => 'sha1'
                                ],
                                [
                                    'caption'=> 'SHA224',
                                    'value'  => 'sha224'
                                ],
                                [
                                    'caption'=> 'SHA256',
                                    'value'  => 'sha256'
                                ],
                                [
                                    'caption'=> 'SHA384',
                                    'value'  => 'sha384'
                                ],
                                [
                                    'caption'=> 'SHA512',
                                    'value'  => 'sha512'
                                ]
                            ],
                            'type'   => 'Select',
                            'visible'=> $version == 3
                        ],
                        [
                            'caption' => 'Private',
                            'name'    => 'Private',
                            'type'    => 'CheckBox',
                            'onChange'=> 'if($Version == 3 && $Private){SNMP_Private($id, true);}else{SNMP_Private($id, false);}'
                        ],
                        [
                            'caption'=> 'Private Password',
                            'name'   => 'PrivatePassword',
                            'type'   => 'PasswordTextBox',
                            'visible'=> $version == 3 && $private
                        ],
                        [
                            'caption' => 'Private Encription',
                            'type'    => 'Select',
                            'name'    => 'PrivMech',
                            'visible' => $version == 3 && $private,
                            'options' => [
                                [
                                    'caption'=> 'DES',
                                    'value'  => 'des'
                                ],
                                [
                                    'caption'=> 'AES128',
                                    'value'  => 'aes128'
                                ],
                                [
                                    'caption'=> '3DES',
                                    'value'  => '3des'
                                ],
                                [
                                    'caption'=> 'AES192',
                                    'value'  => 'AES192'
                                ],
                                [
                                    'caption'=> 'AES256',
                                    'value'  => 'AES256'
                                ],
                                [
                                    'caption'=> 'AES192blu',
                                    'value'  => 'AES192blu'
                                ],
                                [
                                    'caption'=> 'AES256blu',
                                    'value'  => 'AES256blu'
                                ]
                            ]
                        ],
                        [
                            'caption' => 'Show only OIDs with a MIB match',
                            'type'    => 'CheckBox',
                            'name'    => 'ShowOidMibMatch',

                        ],
                        [
                            'caption' => 'MIB-Files',
                            'type'    => 'List',
                            'name'    => 'Mib',
                            'delete'  => true,
                            'columns' => [
                                [
                                    'caption'=> 'MIB-Files',
                                    'name'   => 'MibFiles',
                                    'edit'   => [
                                        'type'=> 'SelectFile',
                                    ],
                                    'add'   => '',
                                    'width' => 'auto'
                                ]
                            ],
                            'add'    => true,
                            'values' => []
                        ],
                    ]
                ],
                [
                    'type'    => 'NumberSpinner',
                    'caption' => 'TimerInterval',
                    'name'    => 'TimerInterval',
                    'suffix'  => 'sec'
                ],
                [
                    'caption'=> 'The search is still active',
                    'type'   => 'ProgressBar',
                    'name'   => 'Bar',
                    'visible'=> false
                ]
            ],
            'actions'=> [
                [
                    'caption'=> 'OIDs',
                    'name'   => 'OidList',
                    'type'   => 'List',
                    'onEdit' => 'SNMP_CreateVariable($id, $OidList);',
                    'columns'=> [
                        [
                            'caption'=> 'OID',
                            'name'   => 'Oid',
                            'width'  => '250px',
                            'edit'   => [
                                'type'=> 'ValidationTextBox'
                            ],
                            'editable' => false
                        ],
                        [
                            'caption' => 'Name',
                            'name'    => 'OidName',
                            'width'   => '175px',
                            'edit'    => [
                                'type' => 'ValidationTextBox'
                            ], 'editable' => false
                        ],
                        [
                            'caption' => 'Description',
                            'name'    => 'OidDescription',
                            'width'   => '175px',
                            'edit'    => [
                                'type' => 'ValidationTextBox'
                            ], 'editable' => false
                        ],
                        [
                            'caption'=> 'Value',
                            'name'   => 'OidValue',
                            'width'  => 'auto',
                            'edit'   => [
                                'type'=> 'ValidationTextBox'
                            ], 'editable' => false
                        ],
                        [
                            'caption' => 'Checkbox',
                            'name'    => 'Checkbox',
                            'width'   => '100px',
                            'edit'    => [
                                'type' => 'CheckBox'
                            ]
                        ]
                    ],
                    'values'=> []
                ]
            ]
        ]);
    }

    public function VersionChange(int $version)
    {
        $v3 = ['User', 'Password', 'AuthMech', 'Private', 'PrivatePassword', 'PrivMech'];
        $v2 = ['Community'];
        switch ($version) {
            case 1:
            case 2:
                $true = $v2;
                $false = $v3;
                break;
            case 3:
                $true = $v3;
                $false = $v2;
                break;
        }

        foreach ($true as $field) {
            $this->UpdateFormField($field, 'visible', true);
        }

        foreach ($false as $field) {
            $this->UpdateFormField($field, 'visible', false);
        }
    }

    public function UpdateValues()
    {
        $children = IPS_GetChildrenIDs($this->InstanceID);

        $snmp = $this->getSNMP();

        foreach ($children as $child) {
            $objectIdent = IPS_GetObject($child)['ObjectIdent'];
            $ident = str_replace('_', '.', $objectIdent);
            $value = $snmp->getValue($ident);

            $this->SetValue($objectIdent, $value);
        }
    }

    public function Private(bool $bool)
    {
        $this->UpdateFormField('PrivatePassword', 'visible', $bool);
        $this->UpdateFormField('PrivMech', 'visible', $bool);
    }

    public function CreateVariable(object $value)
    {
        $ident = str_replace('.', '_', $value['Oid']);
        if ($value['Checkbox']) {
            $name = $value['OidName'] == '' ? $ident : $value['OidName'];

            if (is_numeric($value['OidValue'])) {
                $this->RegisterVariableFloat($ident, $name);
            } else {
                $this->RegisterVariableString($ident, $name);
            }
            $this->SetValue($ident, $value['OidValue']);
        } else {
            $this->UnregisterVariable($ident);
        }
    }

    public function SetMib()
    {
        $list = json_decode($this->ReadPropertyString('Mib'), true);
        if (count($list) == 0) {
            return;
        }

        foreach ($list as $row) {
            $item = $row['MibFiles'];
            $content = base64_decode($item);
            $xml = simplexml_load_string($content);
            $entrys = $xml->list->entry;
            $mib = [];

            foreach ($entrys as $entry) {
                $oid = trim(strval($entry->oid));
                $name = trim(strval($entry->indicator));
                $description = trim(strval($entry->description));

                $mib[$oid] = [
                    'name'        => $name,
                    'description' => $description
                ];
            }
        }
        $this->SetBuffer('Mib', json_encode($mib));
    }

    public function Prepare()
    {
        $host = $this->ReadPropertyString('Host');

        //Get the Assossisations
        $mib = json_decode($this->GetBuffer('Mib'), true);

        //The version is 1,2 or 3
        if ($host != '') {
            $snmp = $this->getSNMP();

            try {
                $values = $this->getOID($snmp, $mib);
            } catch (SnmpRequestException $e) {
                echo $e->getMessage();
                return;
            }

            $this->UpdateFormField('OidList', 'values', json_encode($values));
            $this->UpdateFormField('Bar', 'visible', false);
        }
    }

    private function getOID(SnmpClient $snmp, $mib)
    {
        $walk = $snmp->walk('1.3.6.1.4');

        $bool = true;
        $oids = [];

        $this->UpdateFormField('Bar', 'visible', true);
        $this->UpdateFormField('Bar', 'maximum', 1);
        $this->UpdateFormField('Bar', 'current', 0);

        //get the children Idents
        $children = IPS_GetChildrenIDs($this->InstanceID);
        $childrenIdents = [];

        foreach ($children as $child) {
            array_push($childrenIdents, IPS_GetObject($child)['ObjectIdent']);
        }

        # Keep the walk going until there are no more OIDs left
        while ($bool && $walk->hasOids()) {
            try {
                # Get the next OID in the walk
                $oid = $walk->next();

                //Check if the Value is a valid UTF-String
                if (preg_match('//u', strval($oid->getValue()))) {
                    $value = strval($oid->getValue());
                } else {
                    $value = 'Value can not display';
                    //$value = bin2hex(strval($oid->getValue()));
                }

                $ident = str_replace('.', '_', $oid->getOID());

                $found = in_array($ident, $childrenIdents);

                array_push($oids, ['Oid' => sprintf('%s', $oid->getOid()), 'OidValue' => $value, 'Checkbox' => $found]);

                //Hard Cut at 10000 Elements, the php limit is happy
                if (count($oids) == 10000) {
                    $bool = false;
                }
            } catch (\Exception $e) {
                # If we had an issue, display it here (network timeout, etc)
                echo 'Unable to retrieve OID. ' . $e->getMessage() . PHP_EOL;
            }
        }
        $this->UpdateFormField('Bar', 'maximum', count($oids));
        $current = 0;

        if ($mib != '') {
            $show = [];
            //add the Name and Description of the Mib to Oids
            foreach ($oids as $oidkey => $oid) {
                //cut the last number
                $key = $oid['Oid'];
                $len = strrpos($key, '.');
                $key = substr($key, 0, $len);

                if (array_key_exists($key, $mib)) {
                    $oids[$oidkey]['OidName'] = $mib[$key]['name'];
                    $oids[$oidkey]['OidDescription'] = $mib[$key]['description'];

                    array_push($show, $oids[$oidkey]);
                }

                $current++;
                $this->UpdateFormField('Bar', 'current', $current);
            }
        }

        $this->SetBuffer('SearchActive', json_encode(false));
        $this->UpdateFormField('Bar', 'visible', false);

        if ($this->ReadPropertyBoolean('ShowOidMibMatch') === true && count($show) != 0) {
            return $show;
        } else {
            return $oids;
        }
    }

    private function getSNMP()
    {
        $version = $this->ReadPropertyInteger('Version');
        $host = $this->ReadPropertyString('Host');

        if ($version == 3) {
            $password = $this->ReadPropertyString('Password');
            $private = $this->ReadPropertyBoolean('Private');
            if ($password == '') {
                $snmp = new SnmpClient([
                    'host'    => $host,
                    'version' => 3,
                    'user'    => $this->ReadPropertyString('User'),
                ]);
            } elseif (!$private) {
                $snmp = new SnmpClient([
                    'host'      => $host,
                    'version'   => 3,
                    'user'      => $this->ReadPropertyString('User'),
                    'use_auth'  => true,
                    'auth_mech' => $this->ReadPropertyString('AuthMech'),
                    'auth_pwd'  => $password,
                ]);
            } else {
                $snmp = new SnmpClient([
                    'host'      => $host,
                    'version'   => 3,
                    'user'      => $this->ReadPropertyString('User'),
                    'use_auth'  => true,
                    'auth_mech' => $this->ReadPropertyString('AuthMech'),
                    'auth_pwd'  => $password,
                    'use_priv'  => true,
                    'priv_mech' => $this->ReadPropertyString('PrivMech'),
                    'priv_pwd'  => $this->ReadPropertyString('PrivatePassword'),
                ]);
            }
        } else {
            $this->SendDebug('Version', $version, 0);
            $snmp = new SnmpClient([
                'host'      => $host,
                'version'   => $version,
                'community' => $this->ReadPropertyString('Community')
            ]);
        }

        return $snmp;
    }
}
