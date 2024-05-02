    --------------------------------------------------------------------
    Invision Community <= 4.7.15 (store.php) SQL Injection Vulnerability
    --------------------------------------------------------------------
    
    author..............: Egidio Romano aka EgiX
    mail................: n0b0d13s[at]gmail[dot]com
    software link.......: https://invisioncommunity.com
    
    +-------------------------------------------------------------------------+
    | This proof of concept code was written for educational purpose only.    |
    | Use it at your own risk. Author will be not responsible for any damage. |
    +-------------------------------------------------------------------------+
    
    [-] Vulnerability Description:
      
    The vulnerability is located in the /applications/nexus/modules/front/store/store.php script.
    Specifically, into the IPS\nexus\modules\front\store\_store::_categoryView() method: user
    input passed through the "filter" request parameter is not properly sanitized before being
    assigned to the $where and $joins variables, which are later used to execute some SQL
    queries. This can be exploited by unauthenticated attackers to carry out time-based
    or error-based SQL Injection attacks.
    
    [-] Original Advisory:

    https://karmainsecurity.com/KIS-2024-02

    +-------------------------------------------------------------------------+
    |            This IS a BACKUP with fixed code for cloudflare              |
    +-------------------------------------------------------------------------+
