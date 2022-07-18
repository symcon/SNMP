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

        //Buffer
        $this->SetBuffer('SearchActive', json_encode(true));
        $this->SetBuffer('Mib', json_encode(''));
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
                            'onChange'=> 'SNMP_versionChange($id, $Version);',
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
                            'onChange'=> 'if($Version == 3 && $Private){SNMP_private($id, true);}else{SNMP_private($id, false);}'
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
                    'type' => 'NumberSpinner',
                    ''
                ],
                [
                    'caption'=> 'The search is still active',
                    'type'   => 'ProgressBar',
                    'name'   => 'Bar',
                    'visible'=> false
                ]
            ],
            'actions'=> [
                /* Only for testing
                [
                    'type'    => 'Button',
                    'caption' => 'Set file content',
                    'onClick' => 'SNMP_setMib($id);'
                ],
                [
                    'type'    => 'Button',
                    'caption' => 'Prepare',
                    'onClick' => 'SNMP_prepare($id);'
                ],*/
                [
                    'caption'=> 'OIDs',
                    'name'   => 'OidList',
                    'type'   => 'List',
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
                            'name'    => 'checkbox',
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

    public function versionChange(int $version)
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

    public function private(bool $bool)
    {
        $this->UpdateFormField('PrivatePassword', 'visible', $bool);
        $this->UpdateFormField('PrivMech', 'visible', $bool);
    }

    public function setMib()
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

            //$this->SendDebug("Entrys", print_r($entrys, true), 0);
            $mib = [];

            foreach ($entrys as $entry) {
                //$this->SendDebug("Entry", print_r($entry, true), 0);
                $oid = trim(strval($entry->oid));
                // $this->SendDebug("OID", print_r($oid, true), 0);
                $name = trim(strval($entry->indicator));
                //$this->SendDebug("Name", print_r($name, true), 0);
                $description = trim(strval($entry->description));
                //$this->SendDebug("Description", print_r($description, true), 0);

                $mib[$oid] = [
                    'name'        => $name,
                    'description' => $description
                ];
            }
        }
        $this->SendDebug('Array', print_r($mib, true), 0);
        $this->SetBuffer('Mib', json_encode($mib));
    }

    public function prepare()
    {
        $this->SendDebug('Prepare', 'Start', 0);
        $host = $this->ReadPropertyString('Host');
        $version = $this->ReadPropertyInteger('Version');

        //Get the Assossisations
        $mib = json_decode($this->GetBuffer('Mib'), true);

        //The version is 1,2 or 3
        if ($host != '') {
            if ($version == 3) {
                $this->SendDebug('Version', '3', 0);
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

            try {
                $values = $this->getOID($snmp, $mib);
            } catch (SnmpRequestException $e) {
                //$this->SendDebug("Error:", $e->getMessage(), 0);
                echo $e->getMessage();
                return;
            }
            //$this->SendDebug('Assoc', print_r($assoc,true), 0);

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
                array_push($oids, ['Oid' => sprintf('%s', $oid->getOid()), 'OidValue' => $value]);

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

        $this->SendDebug('Oid-Elements', count($oids), 0);
        $this->SetBuffer('SearchActive', json_encode(false));
        $this->UpdateFormField('Bar', 'visible', false);

        if ($this->ReadPropertyBoolean('ShowOidMibMatch') === true && count($show) != 0) {
            return $show;
        } else {
            return $oids;
        }
    }
}
