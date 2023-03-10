<?php

namespace SimpleSAML\Module\sqlauth\Auth\Source;

use Exception;
use PDO;
use PDOException;
use SimpleSAML\Error;
use SimpleSAML\Logger;

/**
 * Simple SQL authentication source
 *
 * This class is an example authentication source which authenticates an user
 * against a SQL database.
 *
 * @package SimpleSAMLphp
 */

class SQL extends \SimpleSAML\Module\core\Auth\UserPassBase
{
    /**
     * The first DSN we should connect to.
     */
    private $dsn1;

    /**
     * The second DSN we should connect to.
     */
    private $dsn2;

    /**
     * The username we should connect to the first database with.
     */
    private $username1;

    /**
     * The username we should connect to the first database with.
     */
    private $username2;

    /**
     * The password we should connect to the first database with.
     */
    private $password1;

    /**
     * The password we should connect to the second database with.
     */
    private $password2;

    /**
     * The options that we should connect to the first database with.
     */
    private $options1;

    /**
     * The options that we should connect to the second database with.
     */
    private $options2;

    /**
     * The query we should use in the first database to retrieve the attributes for the user.
     *
     * The username and password will be available as :username and :password.
     */
    private $query;


    /**
     * Constructor for this authentication source.
     *
     * @param array $info  Information about this authentication source.
     * @param array $config  Configuration.
     */
    public function __construct($info, $config)
    {
        assert(is_array($info));
        assert(is_array($config));

        // Call the parent constructor first, as required by the interface
        parent::__construct($info, $config);

        // Make sure that all required parameters are present.
        foreach (['dsn1', 'dsn2', 'username1', 'username2', 'password1', 'password2', 'query',] as $param) {
            if (!array_key_exists($param, $config)) {
                throw new Exception('Missing required attribute \''.$param.
                    '\' for authentication source '.$this->authId);
            }

            if (!is_string($config[$param])) {
                throw new Exception('Expected parameter \''.$param.
                    '\' for authentication source '.$this->authId.
                    ' to be a string. Instead it was: '.
                    var_export($config[$param], true));
            }
        }

        $this->dsn1 = $config['dsn1'];
        $this->dsn2 = $config['dsn2'];
        $this->username1 = $config['username1'];
        $this->username2 = $config['username2'];
        $this->password1 = $config['password1'];
        $this->password2 = $config['password2'];
        $this->query = $config['query'];
        if (isset($config['options1'])) {
            $this->options1 = $config['options1'];
        }
        if (isset($config['options2'])) {
            $this->options2 = $config['options2'];
        }
    }


    /**
     * Create a database 1 connection.
     *
     * @return \PDO  The database connection.
     */
    private function connect()
    {
        try {
            $db = new PDO($this->dsn1, $this->username1, $this->password1, $this->options1);
            $driver = explode(':', $this->dsn1, 2);
            $driver = strtolower($driver[0]);
        } catch (PDOException $e) {
            try {
                $db = new PDO($this->dsn2, $this->username2, $this->password2, $this->options2);
                $driver = explode(':', $this->dsn2, 2);
                $driver = strtolower($driver[0]);
            } catch (PDOException $e) {
                // Obfuscate the password if it's part of the dsn
                $obfuscated_dsn =  preg_replace('/(user|password)=(.*?([;]|$))/', '${1}=***', $this->dsn1);
    
                throw new Exception('sqlauth:' . $this->authId . ': - Failed to connect to \'' .
                    $obfuscated_dsn . '\': ' . $e->getMessage());
            }
        }
        $db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        // Driver specific initialization
        switch ($driver) {
            case 'mysql':
                // Use UTF-8
                $db->exec("SET NAMES 'utf8mb4'");
                break;
            case 'pgsql':
                // Use UTF-8
                $db->exec("SET NAMES 'UTF8'");
                break;
        }

        return $db;
    }

    /**
     * Create a database 2 connection.
     *
     * @return \PDO  The database connection.
     */
    private function connect2()
    {
        try {
            $db2 = new PDO($this->dsn2, $this->username2, $this->password2, $this->options2);
        } catch (PDOException $e) {
            // Obfuscate the password if it's part of the dsn
            $obfuscated_dsn =  preg_replace('/(user|password)=(.*?([;]|$))/', '${1}=***', $this->dsn2);

            throw new Exception('sqlauth:' . $this->authId . ': - Failed to connect to \'' .
                $obfuscated_dsn . '\': ' . $e->getMessage());
        }

        $db2->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

        $driver = explode(':', $this->dsn2, 2);
        $driver = strtolower($driver[0]);

        // Driver specific initialization
        switch ($driver) {
            case 'mysql':
                // Use UTF-8
                $db2->exec("SET NAMES 'utf8mb4'");
                break;
            case 'pgsql':
                // Use UTF-8
                $db2->exec("SET NAMES 'UTF8'");
                break;
        }

        return $db2;
    }

    /**
     * Attempt to log in using the given username and password.
     *
     * On a successful login, this function should return the users attributes. On failure,
     * it should throw an exception. If the error was caused by the user entering the wrong
     * username or password, a \SimpleSAML\Error\Error('WRONGUSERPASS') should be thrown.
     *
     * Note that both the username and the password are UTF-8 encoded.
     *
     * @param string $username  The username the user wrote.
     * @param string $password  The password the user wrote.
     * @return array  Associative array with the users attributes.
     */
    protected function login($username, $password)
    {
        assert(is_string($username));
        assert(is_string($password));

        $db1 = $this->connect();

        try {
            $sth = $db1->prepare($this->query);
        } catch (PDOException $e) {
            throw new Exception('sqlauth:'.$this->authId.
            ': - Failed to prepare query: '.$e->getMessage());
        }

        try {
            $sth->execute(['username' => $username, 'password' => $password]);
        } catch (PDOException $e) {
            throw new Exception('sqlauth:'.$this->authId.
            ': - Failed to execute query: '.$e->getMessage());
        }

        try {
            $data = $sth->fetchAll(PDO::FETCH_ASSOC);
        } catch (PDOException $e) {
            throw new Exception('sqlauth:'.$this->authId.
            ': - Failed to fetch result set: '.$e->getMessage());
        }

        Logger::info('sqlauth:'.$this->authId.': Got '.count($data).
            ' rows from database');

        if (count($data) === 0) {
            // No rows returned - invalid username/password
            $db2 = $this->connect2();
            try {
                $sth = $db2->prepare($this->query);
            } catch (PDOException $e) {
                throw new Exception('sqlauth:'.$this->authId.
                ': - Failed to prepare query: '.$e->getMessage());
            }

            try {
                $sth->execute(['username' => $username, 'password' => $password]);
            } catch (PDOException $e) {
                throw new Exception('sqlauth:'.$this->authId.
                ': - Failed to execute query: '.$e->getMessage());
            }

            try {
                $data = $sth->fetchAll(PDO::FETCH_ASSOC);
            } catch (PDOException $e) {
                throw new Exception('sqlauth:'.$this->authId.
                ': - Failed to fetch result set: '.$e->getMessage());
            }

            Logger::info('sqlauth:'.$this->authId.': Got '.count($data).
            ' rows from database');

            if (count($data) === 0) {
                Logger::error('sqlauth:'.$this->authId.
                ': No rows in result set. Probably wrong username/password.');
                throw new Error\Error('WRONGUSERPASS');
            }
        }

        /* Extract attributes. We allow the resultset to consist of multiple rows. Attributes
        * which are present in more than one row will become multivalued. null values and
        * duplicate values will be skipped. All values will be converted to strings.
        */
        $attributes = [];
        foreach ($data as $row) {
            foreach ($row as $name => $value) {
                if ($value === null) {
                    continue;
                }

                $value = (string) $value;

                if (!array_key_exists($name, $attributes)) {
                    $attributes[$name] = [];
                }

                if (in_array($value, $attributes[$name], true)) {
                    // Value already exists in attribute
                    continue;
                }

                $attributes[$name][] = $value;
            }
        }

        Logger::info('sqlauth:'.$this->authId.': Attributes: '.
            implode(',', array_keys($attributes)));

        return $attributes;
    }

}
