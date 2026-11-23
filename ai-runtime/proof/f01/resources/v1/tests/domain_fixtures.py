"""Literal synthetic domains, deliberately distinct IDs; no runtime-derived facts."""
import copy

HEADER=['UID','PID','PPID','PGID','C','TTY','STIME','TIME','CMD']
TAGS={'memory':('a2mi','a2mw'),'cpu':('a2ci','a2cw')}

def table(projection):
    rows=[HEADER]+[[str(x['UID']),str(x['rootPID']),str(x['rootPPID']),'1','0','?','00:00','0s',x['CMD']] for x in projection]
    widths=[max(10,max(len(row[i]) for row in rows)+3) for i in range(8)]
    return '\n'.join(''.join(v+' '*(widths[i]-len(v)) for i,v in enumerate(row[:8]))+row[8] for row in rows)+'\n'

def roles(control='memory'):
    a,b=TAGS[control]
    return [{'rootPID':101,'UID':65532,'rootPPID':0,'CMD':a},{'rootPID':102,'UID':65532,'rootPPID':101,'CMD':b}]

def root_binding(fixture):
    facts=fixture['facts'];row=fixture['rows'][0];control='memory' if 'memory' in facts['target']['name'] else 'cpu'
    projection=roles(control)
    facts['rootRoles']={key:copy.deepcopy(facts[key]) for key in ('target','ownership','init')}
    facts['rootRoles'].update(sample=0,counterReadStart=row['counterReadStart'],counterReadEnd=row['counterReadEnd'],
        queryStartedMonotonic=row['monotonic'],queryReceivedMonotonic=row['counterReadStart'],rootProjection=projection,rawResponse=table(projection))


def version2(fixture):
    facts=fixture['facts'];facts['schema']='f01-a2-accounting-v2'
    facts['pidDomains']={'markers':'container-proc','queries':'sandbox-root'}
    root_binding(fixture)
    for witness in facts['witnesses']:
        witness.pop('pids',None)
        witness.update(rootProjection=[copy.deepcopy(facts['rootRoles']['rootProjection'][0])],
                       rawResponse=table([facts['rootRoles']['rootProjection'][0]]))
    return fixture
