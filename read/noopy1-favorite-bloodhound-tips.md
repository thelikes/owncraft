# @n00py1's Favorite favorite BloodHound tips

> Here is a thread with some of my favorite BloodHound tips, for when the built-in queries are just not finding anything for you.

[source](https://twitter.com/n00py1/status/1508868743451090944)

1. Mark any user you compromise as "owned". This is essential to making good queries. You can mark them one by one by right clicking    
    - Using CrackMapExec https://twitter.com/mpgn_x64/status/1417622873359912960
2. Mark high value targets. There are a lot of useful things you can mark as high value that are not default.
    - Find groups that have the "Admin Count" flag set but are not yet marked as high value. If you see any good ones, mark them as high value now.

    ```
    MATCH p = (g:Group {admincount: True}) WHERE NOT EXISTS(g.highvalue) OR g.highvalue = False RETURN g
    ```

    - Alternatively, find groups that do not have the "Admin Count" flag set, but have local admin on computers. The more the better.  Set the most useful ones as high value.

    ```
    MATCH p=(n:Group)-[:AdminTo*1..]->(m:Computer) WHERE NOT n.admincount RETURN p
    ```

    - Find all computers that can perform unconstrained delegation but are not DCs. (Stolen from @Haus3c)

    ```
    MATCH (c1:Computer)-[:MemberOf*1..]->(g:Group) WHERE g.objectid ENDS WITH '-516' WITH COLLECT(http://c1.name) AS domainControllers MATCH (c2:Computer {unconstraineddelegation:true}) WHERE NOT http://c2.name IN domainControllers RETURN c2
    ```

    - Find any object that has inbound control over the domain. Mark them all as high value. Mark the domain as high value also.

    ```
    MATCH p=shortestPath((n)-[r1:MemberOf|AllExtendedRights|GenericAll|GenericWrite|WriteDacl|WriteOwner|Owns*1..]->(u:Domain {name: "http://DOMAIN.COM"})) WHERE NOT http://n.name="http://DOMAIN.COM" RETURN p
    ```

    - Find groups that can reset passwords. Mark these groups as high value.

    ```
    MATCH p=(m:Group)-[r:ForceChangePassword]->(n:User) RETURN m
    ```

    - Now that you have a ton of objects marked as "owned" or "high value", run this one query:

    ```
    MATCH p=shortestPath((g {owned:true})-[*1..]->(n {highvalue:true})) WHERE g<>n return p
    ```

3. This, hopefully, will give you a path. If not, keep trying to get more owned users through password spraying or whatever methods you have, and run it again.
4. If you still need to Kerberoast, run this query to find which kerberoastable users can get you to high value, and prioritize cracking those first.

    ```
    MATCH p=shortestPath((n:User {hasspn:true})-[*1..]->(m:Group {highvalue:true})) RETURN p
    ```

5. If all your owned users seem truly useless, thy these queries to see if they can do ANYTHING at all: 

    ```
    MATCH p = (g:User {owned: True})-[r]->(n) WHERE r.isacl=true RETURN p

    MATCH p = (g1:User {owned: True})-[r1:MemberOf*1..]->(g2:Group)-[r2]->(n) WHERE r2.isacl=true RETURN p
    ```