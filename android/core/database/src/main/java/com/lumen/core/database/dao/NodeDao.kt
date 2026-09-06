package com.lumen.core.database.dao

import androidx.room.Dao
import androidx.room.Delete
import androidx.room.Insert
import androidx.room.OnConflictStrategy
import androidx.room.Query
import androidx.room.Update
import com.lumen.core.database.model.NodeEntity
import kotlinx.coroutines.flow.Flow

@Dao
interface NodeDao {
    @Query("SELECT * FROM nodes")
    fun getNodes(): Flow<List<NodeEntity>>

    @Query("SELECT * FROM nodes WHERE id = :id")
    fun getNodeById(id: String): Flow<NodeEntity?>

    @Query("SELECT * FROM nodes WHERE id IN (:ids)")
    suspend fun getNodesByIds(ids: List<String>): List<NodeEntity>

    @Query("SELECT * FROM nodes WHERE subscriptionId = :subscriptionId")
    fun getNodesForSubscription(subscriptionId: String): Flow<List<NodeEntity>>

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertNode(node: NodeEntity)

    @Insert(onConflict = OnConflictStrategy.REPLACE)
    suspend fun insertNodes(nodes: List<NodeEntity>)

    @Update
    suspend fun updateNode(node: NodeEntity)

    @Query("UPDATE nodes SET pingMs = :pingMs WHERE id = :id")
    suspend fun updatePing(id: String, pingMs: Int?)

    @androidx.room.Transaction
    suspend fun updatePingsBatch(pings: List<Pair<String, Int?>>) {
        for ((id, pingMs) in pings) {
            updatePing(id, pingMs)
        }
    }

    @Delete
    suspend fun deleteNode(node: NodeEntity)

    @Query("DELETE FROM nodes WHERE id = :id")
    suspend fun deleteNodeById(id: String)

    @Query("DELETE FROM nodes WHERE subscriptionId = :subscriptionId")
    suspend fun deleteNodesBySubscription(subscriptionId: String)

    @Query("DELETE FROM nodes WHERE subscriptionId IS NULL")
    suspend fun deleteManualNodes()

    @Query("DELETE FROM nodes")
    suspend fun clearAllNodes()
}
