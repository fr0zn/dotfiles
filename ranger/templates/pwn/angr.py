import angr
import claripy

name = ''

avoid = []

find = []

# PIE
# proj = angr.Project(name, main_opts={'base_addr': 0})

proj = angr.Project(name)

argv1 = 'SnwWh1te'
argv2 = claripy.BVS("argv2", 16 * 8)

initial_state = proj.factory.entry_state(args=[name, argv1, argv2])

simgr = proj.factory.simgr(initial_state)

simgr.explore(find=find, avoid=avoid)

s = simgr.found[0]

solution = s.solver.eval(argv2, cast_to=bytes)

print(solution)

