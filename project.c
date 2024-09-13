#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <signal.h>
#include <dirent.h>
#include <stdlib.h> //strtol
#include <stdbool.h> //Boolean
#include <dirent.h> // Dirent ops
#include <fcntl.h> //open ops
#include<ctype.h>
#define ARRAY_MAX_SIZE 1024 // size of Array

//Utility function to access directory 
DIR* accessDirectory(const char *path){
    DIR *directory = opendir(path); //Open the directory via the opendir function
    if (directory == NULL) { //If failes to open
        printf("Error in accesing '%s' directory", path);
    }
    return directory; //Return directory on success.
}

//Utility function to access Stat files 
FILE* accessProcessStatFile(pid_t pid) {
    char path[50];
    sprintf(path, "/proc/%d/stat", pid); //COnstructing path to access the process statistics file
    FILE *StatFile = fopen(path, "r"); //Opens in read mode
    if (StatFile == NULL) { //If failes to open
        //printf("Error in accesing file '%s'", path);
    }
    return StatFile; //Return Stat file on success
}

//Utility function to extract Process state from a Stat File
char extractProcessState(FILE *processStatFile) {
    if(!processStatFile){ //Return null if file is null
        return '\0';
    }
    char ProcessState;
    char buffer[512]; 

    //Reads from the process stat file and adds the details to the buffer
    if (fgets(buffer, sizeof(buffer), processStatFile)) { 

        //From the buffer, we read the proces State avoiding what is not needed in the start of the file.
        if (sscanf(buffer, "%*d %*s %c", &ProcessState) == 1) {
            return ProcessState;
        }
    }

    return '\0'; //If fails
}

//Extracting Parent Process ID from a Process ID
pid_t getParentPID(pid_t pid) {

    //Accesing process Stat File, as has detaild info of the process
    FILE *processStatFile = accessProcessStatFile(pid);
    if(!processStatFile){
        return -1;
    }

    pid_t parentId = -1; //Initializing to invalid
    char buffer[512];

    //Reads from the process stat file and adds the details to the buffer
    if(fgets(buffer, sizeof(buffer), processStatFile)){
        //printf("Buffer: %s\n", buffer);
        
        //From the buffer, we rea the parentID avoiding what is not needed in the start of the file.
        if(sscanf(buffer, "%*d %*s %*c %d", &parentId) != 1){ 
            //printf("Unable to parse from buffer.\n");
            parentId = -1;
        }
    }else{
        //printf("Cannot read details from file: %s\n", processStatFile);
        parentId = -1;
    }

    fclose(processStatFile); //Close & retn the parent ID extracted.
    return parentId;
}

//Checks if process ID belongs to the process tree wrt Root Process
bool descendantCheck(pid_t rootProcess, pid_t processID){

    //Iterates to get parent of processID until prooces ID is not 1, as 1 reserved fir init. 
    //And until processID matches the root process
    do{
        processID = getParentPID(processID);
        if(processID == -1){
            return false;
        }
    }while (processID > 1 && processID != rootProcess);

    //Return TRUE if process ID which is updated with parent ID in a loop, matches the root process
    return (processID == rootProcess) ? true : false; 
}

//Check if root has descendants
void getDescendants(pid_t rootProcess, pid_t *descendantsArr, int *totalDescendants){

    //Accessing process directory as contains processes
    DIR *processDIR = accessDirectory("/proc");
    if(processDIR == NULL) exit(EXIT_FAILURE);

    struct dirent *processEntry; //Structure to get information about the directory
    pid_t pid, ppid; //To know abot the parent child relationsship
    int index = *totalDescendants; //To maintain index when adding to end of array

    //Iterates over the process Directory to get Process Details, untill all process entries have been visited
    do {
        //Read the entries in the directory stream
        processEntry = readdir(processDIR); 

        if (processEntry != NULL) { //If details are present in the processEntry

            //The directory name is converted to a process ID
            pid_t pid = strtol((*processEntry).d_name, NULL, 10);

            //Checks if is a directory ad the process is not 0, as if numbers are not deteted strtol converts to simpel 0
            if ((*processEntry).d_type == DT_DIR && pid !=0 ) {

                pid_t ppid = getParentPID(pid); //Get parent ID to identify hierarchy

                //Chekc the hierarchy to see if descendant of root Process ID
                if (ppid == rootProcess) { 
                    //printf("Found descendant: PID = %d\n", pid);

                    //Check if space in array
                    if(index < ARRAY_MAX_SIZE){
                        descendantsArr[index]=pid; //Add PID to the array
                        index++; //Increment, so other PID can be added
                    }else{ //If array size falls shot
                        printf("Descendants array is full.\n");
                        closedir(processDIR);
                        exit(EXIT_FAILURE);
                    }

                    //Recruse call using current PID which now acts as the root process.
                    //Allows to check for more descendants
                    getDescendants(pid, descendantsArr, &index);
                }
            }
        }
    } while (processEntry != NULL);

    //Assigning the index value to total Descendants, as count reference
    *totalDescendants = index;

    //Closing the directory
    closedir(processDIR);
}

//Takes in a process and key to identify the task to perform
void processDescHandler(pid_t rootProcess, char *key){

    //Arry that will contain the process IDs that belong to the root process
    pid_t descendantsArr[ARRAY_MAX_SIZE];
    int totalDescendants = 0;

    //Extracting all the descendants via getDescendants function.
    getDescendants(rootProcess, descendantsArr, &totalDescendants);

    //Check if there are any descendants
    if(totalDescendants > 0){

        int descendantTracker = 0;

        //Iterating over the process ID in the descendants array in reverse
        int i = totalDescendants - 1;
        while(i>=0){

            //Cater to Kill the Descendant Processes
            if(strcmp(key, "SIGKILL") == 0){
                //Killing the descendants using SIGKILL signal
                int result = kill(descendantsArr[i], SIGKILL);
                printf(result == 0 ? "Successfully killed %d\n" : "Failed to kill %d\n", descendantsArr[i]);
            }

            //Cater to Stopping the Descendant Processes
            if(strcmp(key, "SIGSTOP") == 0){
                //Stopping the descendants using SIGSTOP signal
                int result = kill(descendantsArr[i], SIGSTOP);
                printf(result == 0 ? "Successfully stopped %d\n" : "Failed to stop %d\n", descendantsArr[i]);
            }

            //Cater to Continuing the Paused Descendant Processes
            if(strcmp(key, "SIGCONT") == 0){
                //Continuing the paused descendants using SIGCONT signal
                int result = kill(descendantsArr[i], SIGCONT);
                printf(result == 0 ? "Successfully contined %d\n" : "Failed to continue %d\n", descendantsArr[i]);
            }

            //Cater to listing non direct descenandants of a process
            if(strcmp(key, "NON-DIRECT") == 0){
                pid_t ppid = getParentPID(descendantsArr[i]); //Get Parent PID of descendants
                if( ppid != rootProcess ){ //Check if parent PID does not match process
                    printf("%d is non direct descendant\n", descendantsArr[i]);
                    descendantTracker = 1;
                }
            }

            //Caters to listing Direct descendants
            if(strcmp(key, "DIRECT") == 0){
                pid_t ppid = getParentPID(descendantsArr[i]); //Get Parent PID of descendants
                if( ppid == rootProcess ){ //Check if parent PID matches process
                    printf("%d is direct descendant\n", descendantsArr[i]);
                }

            }

            //Caters to lisitng the grandchildren of the process
            if(strcmp(key, "GRANDCHILDREN") == 0){
                pid_t pid = descendantsArr[i]; 
                pid_t ppid = getParentPID(pid); //Get Parent PID of descendants
                //Checks if is the grandparent of process
                if(getParentPID(ppid) == rootProcess){ 
                    printf("Process %d is a grandchild of %d\n", pid, rootProcess);
                }
            }

            //Caters to list the zombie descendants
            if(strcmp(key, "DEFUNCT") == 0){
                pid_t pid = descendantsArr[i];

                //Access the process Stat File using the accessProcessStatFile function
                FILE *processStatFile = accessProcessStatFile(pid);

                //Extract process state via extractProcessState function
                char ProcessState = extractProcessState(processStatFile);

                //If state identified as Zombie list the descendan'ts process ID
                if (ProcessState == 'Z') {
                    printf("%d is a Defunct descendant of %d\n", pid, rootProcess);
                    descendantTracker = 1;
                }

                fclose(processStatFile);
            }

            //Cater to killing the parents of zombie processes
            if(strcmp(key, "KILL-ZOMBIE") == 0){
                pid_t pid = descendantsArr[i];
                FILE *processStatFile = accessProcessStatFile(pid); //Access the process stat file
                char ProcessState;
                pid_t parentID;

                //Reading the Process State and ParentID from the statistics file
                if (fscanf(processStatFile, "%*d %*s %c %d", &ProcessState, &parentID) == 2) {
                    //printf("%c\n", ProcessState);
                    //Check if process state is Zombie then kill it using SIGKILL signal
                    if (ProcessState == 'Z') {
                        printf("%d is a Defunct descendant of %d\n", pid, rootProcess);
                        int result = kill(parentID, SIGKILL);
                        printf(result == 0 ? "Successfully killed parent %d\n" : "Failed to kill parent %d\n", descendantsArr[i]);
                    }
                }

                fclose(processStatFile);
            }
            
            i--;
        } 
        
        //If process no direct descenandtss
        if(descendantTracker == 0 && key == "NON-DIRECT"){
            printf("No non direct descedants\n");
        }

        //If process has no defunct descendants
        if(descendantTracker == 0 && key == "DEFUNCT"){
            printf("Process %d has no Defunct descendants\n", rootProcess);
        }
    }else{
        printf("Process %d has no descendants.\n", rootProcess);
    }

}


//Function to kill the process ID by the rootProcess
void rootKILLProcessID(pid_t rootProcess, pid_t processID){
    
    //Checks if belongs to the process tree rooted at root process
    if(descendantCheck(rootProcess, processID)){
        //If is part of the process tree, it is terminated using SIGKILL
        int result = kill(processID, SIGKILL);
        printf(result == 0 ? "Successfully killed %d\n" : "Failed to kill %d\n", processID);
    }else{
        printf("%d does not belong to %d root process.\n", processID, rootProcess);
    }
}



//List sibling processes
void processSiblings(pid_t processID, char *key){
    int siblingTracker = 0; //Variable to update if a normal or defunct sibling is identified

    pid_t ppid = getParentPID(processID); //Getting Parent Pricess ID

    //Accessing process directory
    DIR *processDIR = accessDirectory("/proc");
    if(processDIR == NULL) exit(EXIT_FAILURE);

    struct dirent *processEntry; //Structure to get information about the directory

    do {
        //Read directries frn the directory stream
        processEntry = readdir(processDIR); 

        if (processEntry != NULL) {
            pid_t pid = strtol((*processEntry).d_name, NULL, 10); //Convert process Entery name to process ID

            //Checking if the process ID we are searching for siblingss will be excluded
            if ((*processEntry).d_type == DT_DIR && pid != 0 && pid != processID) {

                pid_t siblingParentPID = getParentPID(pid); //Get Parent ID of the processEntry processes

                //Check if siblengs has same parent
                if (siblingParentPID == ppid) {

                    //Cater to if  Siblings are to be listed
                    if(key == "SIBLINGS"){
                        printf("Process %d is a sibling of %d process\n", pid, processID);
                        siblingTracker = 1;
                    }

                    //Cater to if Defunct Siblings are to be listed
                    if(key == "DEFUNCT-SIBLINGS"){
                        FILE *processStatFile = accessProcessStatFile(pid); //Access Process Stat File

                        //If the process stat file contains details extracts the process state  via extractProcessState function
                        if (processStatFile != NULL) {
                            char ProcessState = extractProcessState(processStatFile);

                            //Check process state to see if process is defunct
                            if (ProcessState == 'Z') {
                                printf("%d is a Defunct sibling of %d\n", pid, processID);
                                siblingTracker = 1;
                            }
                        }
                        fclose(processStatFile); //Close process Stat File
                    }
                    
                }
            }
        }
    } while (processEntry != NULL);

    //If process has no siblings
    if(key == "SIBLINGS" && siblingTracker == 0){ 
        printf("Process %d has no siblings\n", processID);
    }

    //If process has no Defunct Sibling
    if(key == "DEFUNCT-SIBLINGS" && siblingTracker == 0){ 
        printf("Process %d has no Defunct siblings\n", processID);
    }

    //Closing the directory
    closedir(processDIR);
}

//List the status of the process ID
void showProcessStatus(pid_t processID){
    //Access the process Stat File using the accessProcessStatFile function
    FILE *processStatFile = accessProcessStatFile(processID);

    //If the processStatFile contains process details, utilize it to get the process State via extractProcessState function
    if (processStatFile != NULL) {

        char ProcessState = extractProcessState(processStatFile);

        //Print the results be identifying Z for Defunct States
        printf(ProcessState == 'Z' ? "Process %d state is Defunct\n" : "Process %d State is Not Defunct\n", processID);
    }
    fclose(processStatFile); //Close the process Stat File
}

int main(int argc, char *argv[]){

    // Checking if the process ID belngs to the procss tree rooted at provided root process
    if(argc == 3){
        // Converting Root & Process ID string arguments to numbers
        pid_t rootProcess = strtol(argv[1], NULL, 10); //String, End Ptr, Base
        pid_t processID = strtol(argv[2], NULL, 10);
        printf("-Root Process: %d\n-Process ID: %d\n", rootProcess, processID);
        
        // Check Processes must be greater then 1. As 1 is reserved fo init
        if(rootProcess <=1 || processID <=1 ){
            printf("Invalid Processes.\n");
            exit(EXIT_FAILURE);
        }

        // Check if process ID is a descendant of root process ID
        if (descendantCheck(rootProcess, processID)) {
            pid_t ppid = getParentPID(processID); //Getting parent of the processID to display
            printf("Process %d belongs to the tree rooted at root process %d.\n", processID, rootProcess);
            printf("Process ID: %d, Parent Process ID: %d\n", processID, ppid);
        }else{
            printf("Process %d does not belong to the tree rooted at root process %d.\n", processID, rootProcess);
        }
    }
    else if(argc == 4){ //Running with options

        char *option = argv[1]; //Assigning option
        //printf("Option: %s\n", option);

        //Converting Root & Process ID string arguments to numbers
        int rootProcess = strtol(argv[2], NULL, 10);
        int processID = strtol(argv[3], NULL, 10);
        printf("-Option: %s \n-Root Process: %d \n-Process ID: %d\n", option, rootProcess, processID);
        
        // Processes must be greatr then 1. As 1 is reserved for init
        if(rootProcess <=1 || processID <=1 ){
            printf("Invalid Processes.\n");
            exit(EXIT_FAILURE);
        }

        //Check if process ID belongs to the process tree rooted at root process
        if (!descendantCheck(rootProcess, processID)) {
            printf("Process %d does not belong to the tree rooted at root process %d.\n", processID, rootProcess);
            exit(EXIT_FAILURE);
        }

        if(strcmp(option, "-dx") == 0){ //Option 1: Option -dx Root kills all descendants using sigKill
            processDescHandler(rootProcess, "SIGKILL");
        }
        else if(strcmp(option, "-dt") == 0){ //Option 2: Root sends SIGSTOP all descendants using SIgTOP
            processDescHandler(rootProcess, "SIGSTOP"); 
        }
        else if(strcmp(option, "-dc") == 0){ //Option 3: Root sends SIGCONT all descendants using SIGCONT
            processDescHandler(rootProcess, "SIGCONT");
        }
        else if(strcmp(option, "-rp") == 0){ //Option 4: Root kills Process ID
            rootKILLProcessID(rootProcess, processID);
        }
        else if(strcmp(option, "-nd") == 0){ //Option 5: List tje PIDs of all Non-Direct Descendants of Prcess ID
            processDescHandler(processID, "NON-DIRECT");
        }
        else if(strcmp(option, "-dd") == 0){ //Option 6: List tje PIDs of all Immediate Descendants of Prcess ID
            processDescHandler(processID, "DIRECT"); 
        }
        else if(strcmp(option, "-sb") == 0){ //Option 7: List the PIDs of all sibling processes of Process ID
            processSiblings(processID, "SIBLINGS");
        }
        else if(strcmp(option, "-bz") == 0){ //Option 8: List the PIDs of all sibling processes of Process ID that are Defunct
            processSiblings(processID, "DEFUNCT-SIBLINGS");
        }
        else if(strcmp(option, "-zd") == 0){ //Option 9: Lists the PIDs of all descendents of Process ID that are defunct
            processDescHandler(processID, "DEFUNCT");
        }
        else if(strcmp(option, "-gc") == 0){ //Option 10: lists the PIDs of all the grandchildren of Process ID
            processDescHandler(processID, "GRANDCHILDREN");
        }
        else if(strcmp(option, "-sz") == 0){ //Option 11: Print the status of the Process ID (Defunct / Not Defunct)
            showProcessStatus(processID);
        }
        else if(strcmp(option, "-kz") == 0){ //Option 12: Kills the parents of all zombie process that are the descendants of Process ID
            processDescHandler(processID, "KILL-ZOMBIE");
        }
        else{
            printf("Invalid operation argument '%s' passed.\n", option);
            exit(EXIT_FAILURE);
        }
    }
    else{ //Arguements exceed 4
        printf("Invalid number of arguments provided. Please enter again.\n");
        exit(EXIT_FAILURE);
    }

    return 0;
}