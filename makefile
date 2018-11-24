all:
	@javac -cp ".:/home/codyv/Projects/MillionairesAuction/libs/bcprov-jdk15on-160.jar" -d out/production/BSGS/ src/*.java
	
.PHONY: run
run:
	@time java -cp /home/codyv/Projects/MillionairesAuction/out/production/BSGS:/home/codyv/Projects/MillionairesAuction/libs/bcprov-jdk15on-160.jar PET