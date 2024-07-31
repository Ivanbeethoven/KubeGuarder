<template>
  <div class="indexPage">
    <div class="header">
      <span style="color: black; font-size: 30px">KUBEGUARD</span>
<!--      <img src="../imgs/title.png" alt="title" />-->
    </div>
    <div class="model-list">
      <el-table
        empty-text="No Kubernetes Cluster has been configured"
        :data="clusterList"
        style="width: 100%; border: #373D41 2px solid"
        :header-cell-style="{ background:'black',color:'#FFFFFF'}"
        :cell-style="{ background:'#FFFFFF'}">
        <el-table-column label="K8S 集群列表" header-align="center" align="center">
          <template slot-scope="scope">
            {{ scope.row.host }}
          </template>
        </el-table-column>

        <el-table-column label="操作" header-align="center" align="center">
          <template slot-scope="scope">
            <el-button
                       size="mini" type="info"
                       @click="handleConnect(scope.$index, scope.row)">连接</el-button>
            <el-button type="info"
              size="mini"
              @click="handleEdit(scope.$index, scope.row)">配置</el-button>
            <el-button
              size="mini"
              type="danger"
              @click="handleDelete(scope.$index, scope.row)">删除</el-button>
          </template>
        </el-table-column>

      </el-table>
      <div style="text-align: right;background-color: #FFFFFF; margin-top: 15px">
        <el-button size="small" type="info" @click="dialogFormVisible = true" style="text-align: right; margin-right: 5%; margin-bottom: 10px">添加新集群</el-button>
      </div>
    </div>

    <el-dialog title="K8S Cluster Configuration" :visible.sync="dialogFormVisible">
      <el-form :model="form">
        <el-form-item label="Address" :label-width="formLabelWidth">
          <el-input v-model="form.host" autocomplete="off"></el-input>
        </el-form-item>
        <el-form-item label="Access Token" :label-width="formLabelWidth">
          <el-input type="textarea" v-model="form.token"></el-input>
        </el-form-item>
      </el-form>
      <div slot="footer" class="dialog-footer">
        <el-button @click="dialogFormVisible = false">取 消</el-button>
        <el-button type="info" @click="dialogFormVisible = false">确 定</el-button>
      </div>
    </el-dialog>
  </div>
</template>

<script>

export default {
  name: "Index",
  data() {
    return {
      clusterList: [
        {host: "192.168.137.200:6643", token: "eyJhbGciOiJSUzI1NiIsImtpZCI6IksxOEVtWXF3YzJoX0trWEQwZkE0X29aV3RiakY3VnVxVThlYzNUQjBkN1EifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLWd1YXJkIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRldGVjdG9yLXNhLXNlY3JldCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJkZXRlY3Rvci1zYSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjY3NjgwZDg1LTI5MmUtNDhiZS1hNTcwLTgzNGIyYjQ0OThlYyIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDprdWJlLWd1YXJkOmRldGVjdG9yLXNhIn0.oadh24WLMia5Mtcc9ERY0X9N6t6srv6bzGXEXy85IINgGI287SEMQQ1pxW0KN-bXtKRzK1aAG1sBBYMHlOma4RABqgrNSa-fyTgWwb0r6NqPMCpQ9WuuhR9Aoh18PKimN8i4-NvJFlxmXido0SH91SMS5PrI2-NgZ7N464Qd0IfeKNXwP4egHiT2FjEpq6sQAiN7IL0RCvRdqjnWWHvIyEbSdjHMCDtQ0Xajv9NpM25JJ1cWKs5AlWDHgdtGRPWF9gMJynt304pkhT2rkIWDk75Ua8UMaPH-u2YdEVDS76JCeNtciBBnbfT3NFkgiZoG1jBI8xM3B3o8gE6b1LzXyg"}
      ],

      dialogFormVisible: false,
      form: {
        host: '192.168.189.31:6643',
        token: 'eyJhbGciOiJSUzI1NiIsImtpZCI6IksxOEVtWXF3YzJoX0trWEQwZkE0X29aV3RiakY3VnVxVThlYzNUQjBkN1EifQ.eyJpc3MiOiJrdWJlcm5ldGVzL3NlcnZpY2VhY2NvdW50Iiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9uYW1lc3BhY2UiOiJrdWJlLWd1YXJkIiwia3ViZXJuZXRlcy5pby9zZXJ2aWNlYWNjb3VudC9zZWNyZXQubmFtZSI6ImRldGVjdG9yLXNhLXNlY3JldCIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50Lm5hbWUiOiJkZXRlY3Rvci1zYSIsImt1YmVybmV0ZXMuaW8vc2VydmljZWFjY291bnQvc2VydmljZS1hY2NvdW50LnVpZCI6IjY3NjgwZDg1LTI5MmUtNDhiZS1hNTcwLTgzNGIyYjQ0OThlYyIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDprdWJlLWd1YXJkOmRldGVjdG9yLXNhIn0.oadh24WLMia5Mtcc9ERY0X9N6t6srv6bzGXEXy85IINgGI287SEMQQ1pxW0KN-bXtKRzK1aAG1sBBYMHlOma4RABqgrNSa-fyTgWwb0r6NqPMCpQ9WuuhR9Aoh18PKimN8i4-NvJFlxmXido0SH91SMS5PrI2-NgZ7N464Qd0IfeKNXwP4egHiT2FjEpq6sQAiN7IL0RCvRdqjnWWHvIyEbSdjHMCDtQ0Xajv9NpM25JJ1cWKs5AlWDHgdtGRPWF9gMJynt304pkhT2rkIWDk75Ua8UMaPH-u2YdEVDS76JCeNtciBBnbfT3NFkgiZoG1jBI8xM3B3o8gE6b1LzXyg'
      },
      formLabelWidth: '120px'
    };
  },
  methods: {
    handleConnect(index, row) {
      this.$router.push('/main');
      console.log(index, row);
    },
    handleEdit(index, row) {
      console.log(index, row);
    },
    handleDelete(index, row) {
      console.log(index, row);
    }
  }
}
</script>

<style lang="scss" scoped>
.indexPage {
  display: flex;
  flex-direction: column;
  align-items: center;
}

.header {
  margin-top: 50px;
}

.model-list {
  margin-top: 50px;
  width: 50%;
  background-color: #FFFFFF;
}

</style>
