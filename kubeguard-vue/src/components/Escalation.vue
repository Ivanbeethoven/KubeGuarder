<template>
  <el-container style="height: 100%; padding: 0;">
    <el-aside width="60%" style=" background-color: #B3C0D1">
      <div class="left-title">
        <el-button type="primary"
                   @click=" connectWSServer"
                   style="margin-left: 20px; margin-right: 10px">
          <i v-if="open" class="el-icon-video-pause"></i>
          <i v-else class="el-icon-video-play"></i>
        </el-button>
        <span v-if="open">集群资源操作监控已开启</span>
        <span v-else>集群资源操作监控已关闭</span>

        <el-select v-model="select_type" placeholder="请选择" >
          <el-option
            v-for="item in options"
            :key="item.value"
            :label="item.label"
            :value="item.value">
          </el-option>
        </el-select>
      </div>
      <div class="left-body">
        <el-table
          :data="resultList"
          highlight-current-row
          @row-click="handleRowClick"
          style="width: 100%; font-size: 12px;"
          height="450px"
        >
          <el-table-column prop="operationId" label="Operation ID" width="150" align="center"></el-table-column>
          <el-table-column prop="account" label="Account" width="150" align="center"></el-table-column>
          <el-table-column prop="resource" label="Resource" width="150" align="center"></el-table-column>
          <el-table-column prop="verb" label="Verb" width="80" align="center"></el-table-column>
          <el-table-column
            label="Escalation Types" align="center"
           >
            <template slot-scope="scope">
              {{scope.row.typeFullName}}
              <el-tag v-for="(type, index) in scope.row.typeList"
                size="mini" type="danger"  style="margin-left: 10px; margin-right: 10px">{{ type }}</el-tag>
            </template>
          </el-table-column>
        </el-table>
      </div>
    </el-aside>
    <el-main>
      <div class="details-section" >
        <div style="margin-bottom: 5px">权限提升详情:</div>
        <div class="json-details">
          <pre><code>{{ formattedSelectedRowData }}</code></pre>
        </div>
      </div>
    </el-main>
  </el-container>
</template>

<script>
import {url} from "../js/config";

export default {
  name: "Escalation",
  data(){
    return{
      open: false,
      icon: "el-icon-video-play",
      icon_msg: "集群监控已暂停",
      options: [{
        value: 0,
        label: '全部提权类型'
      }, {
        value: 1,
        label: '凭证窃取'
      }, {
        value: 2,
        label: '账户伪装'
      }, {
        value: 3,
        label: '操作RBAC'
      }, {
        value: 4,
        label: '间接执行'
      }],
      select_type: '',
      selectedResult: '',
      rowIndex: '',
      resultList: [],
      ws: {}
    }
  },
  created() {
    this.getResourceList()
  },
  methods :{
    filterList(list){
      let idList = [
        '097aa0bf-2d57-4649-a40f-e677c5b1ea59',
        '28560cfc-1f9a-4207-aff6-685b27265e44',
        '79b49b18-2ef3-440a-9fd0-dc130e15331a',
        '099ee236-be9c-4eb4-a3b9-46f026fd1343',
        'b085569e-472f-499b-84e3-3ecb52f1404c',
        '3082b745-0e8b-4285-a003-a8af7f744ff7',
        '9f873fce-840c-49e7-990d-c1d3545525a3',
      ]
      return list.filter(obj => idList.includes(obj.operationId))
    },
    getResourceList(){
      this.$http.get(url + "/escalation/results").then(res => {
        let temp = res.data
        let filteredList = this.filterList(temp)
        filteredList.sort(() => Math.random() - 0.5)
        filteredList.forEach(item => temp.unshift(item))
        this.resultList = temp
      })
    },
    handleRowClick(row, rowIndex){
        let temp = row.report
        if(temp.operation.auditID != null){
          temp.operation.operationID = temp.operation.auditID
        }
        delete temp.operation.auditID
        this.selectedResult = temp;
        this.rowIndex = rowIndex;
    },
    connectWSServer(){
      this.open = !this.open

      if(this.open){
        let sid = Math.floor(Math.random() * 8999 + 1000)
        this.ws = new WebSocket("ws://localhost:8080/api/ws/escalation/" + sid)

        //监听是否连接成功
        this.ws.onopen = ()=> {
          console.log('ws连接状态：' +this.ws.readyState);
          //连接成功则发送一个数据
          this.ws.send('连接成功');
        }

        //接听服务器发回的信息并处理展示
        this.ws.onmessage = (data)=> {
          console.log('接收到来自服务器的消息：');
          console.log(data)
        }

        //监听连接关闭事件
        this.ws.onclose = ()=>{
          //监听整个过程中websocket的状态
          console.log('ws连接已关闭');
        }

        //监听并处理error事件
        this.ws.onerror = function(error) {
          console.log(error);
        }
      }else{
        //关闭WS连接
        if(!this.ws.closed){
          this.ws.close()
        }
      }
    }
  },
  computed:{
    formattedSelectedRowData() {
      if (this.selectedResult) {
        return JSON.stringify(this.selectedResult, null, 2);
      }
      return '请选择一行';
    }
  }

}
</script>

<style scoped>
.left-title {
  padding: 10px;
  display: flex;
  align-items: center; /* 垂直居中 */
  justify-content: flex-start; /* 确保内容从左侧开始 */
  border-bottom: 2px solid #FFFFFF;
}

.left-title > .el-select {
  margin-left: auto; /* 自动推到最右边 */
  margin-right: 20px;
}

.details-section{
  height: 100%;
  display: flex;
  flex-direction: column;
}

.json-details {
  padding: 10px;
  background-color: #FFFFFF;
  border: gray solid 2px;
  flex: 1;
  overflow: auto;
}

.el-table >>> .el-table__row--highlight {
  background-color: #0099FF !important;
}

.json-details code {
  color: #2e6da4; /* JSON文本颜色 */
}
</style>
